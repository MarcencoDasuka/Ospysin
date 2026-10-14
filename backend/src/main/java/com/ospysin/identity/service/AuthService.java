package com.ospysin.identity.service;

import com.ospysin.identity.User;
import com.ospysin.identity.UserRepository;
import com.ospysin.identity.api.AuthUserResponse;
import com.ospysin.identity.api.LoginRequest;
import com.ospysin.shared.error.ResourceNotFoundException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final SecurityContextRepository securityContextRepository;
    private final CsrfTokenRepository csrfTokenRepository;
    private final boolean cookieSecure;

    public AuthService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            SecurityContextRepository securityContextRepository,
            CsrfTokenRepository csrfTokenRepository,
            @Value("${COOKIE_SECURE:${server.servlet.session.cookie.secure:false}}") boolean cookieSecure) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.securityContextRepository = securityContextRepository;
        this.csrfTokenRepository = csrfTokenRepository;
        this.cookieSecure = cookieSecure;
    }

    public AuthUserResponse login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        log.info("Attempting authentication for operator '{}'", request.username());

        Authentication authResult = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        // Session fixation defense: rotate existing session ID or create a fresh one
        HttpSession existingSession = httpRequest.getSession(false);
        if (existingSession != null) {
            httpRequest.changeSessionId();
        } else {
            httpRequest.getSession(true);
        }
        HttpSession session = httpRequest.getSession();

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, httpRequest, httpResponse);

        // Ensure fresh CSRF token is generated and attached to response
        CsrfToken freshCsrfToken = csrfTokenRepository.generateToken(httpRequest);
        csrfTokenRepository.saveToken(freshCsrfToken, httpRequest, httpResponse);
        httpRequest.setAttribute(CsrfToken.class.getName(), freshCsrfToken);

        // Explicitly attach hardened JSESSIONID cookie
        Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
        sessionCookie.setPath("/");
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(cookieSecure);
        sessionCookie.setAttribute("SameSite", "Strict");
        httpResponse.addCookie(sessionCookie);

        User user = userRepository.findByUsername(authResult.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + authResult.getName()));

        log.info("Operator '{}' successfully authenticated with role '{}'", user.getUsername(), user.getRole());
        return new AuthUserResponse(user.getId(), user.getUsername(), user.getRole());
    }

    public void logout(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        // Clear cookies
        Cookie clearSessionCookie = new Cookie("JSESSIONID", "");
        clearSessionCookie.setPath("/");
        clearSessionCookie.setMaxAge(0);
        clearSessionCookie.setHttpOnly(true);
        clearSessionCookie.setSecure(cookieSecure);
        clearSessionCookie.setAttribute("SameSite", "Strict");
        httpResponse.addCookie(clearSessionCookie);

        Cookie clearXsrfCookie = new Cookie("XSRF-TOKEN", "");
        clearXsrfCookie.setPath("/");
        clearXsrfCookie.setMaxAge(0);
        clearXsrfCookie.setHttpOnly(false);
        clearXsrfCookie.setSecure(cookieSecure);
        clearXsrfCookie.setAttribute("SameSite", "Strict");
        httpResponse.addCookie(clearXsrfCookie);

        log.info("Operator session successfully invalidated and cookies cleared");
    }

    @Transactional(readOnly = true)
    public AuthUserResponse getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new InsufficientAuthenticationException("Authentication is required to access this resource.");
        }

        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + authentication.getName()));

        return new AuthUserResponse(user.getId(), user.getUsername(), user.getRole());
    }
}
