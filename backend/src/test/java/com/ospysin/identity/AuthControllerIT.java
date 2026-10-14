package com.ospysin.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.AbstractIntegrationTest;
import com.ospysin.identity.api.LoginRequest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class AuthControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /api/auth/login with bootstrapped admin credentials returns 200 OK, AuthUserResponse, and sets JSESSIONID and XSRF-TOKEN cookies")
    void shouldLoginSuccessfullyWithAdminCredentials() throws Exception {
        LoginRequest loginRequest = new LoginRequest("admin", "admin");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(cookie().exists("JSESSIONID"))
                .andExpect(cookie().httpOnly("JSESSIONID", true))
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(cookie().httpOnly("XSRF-TOKEN", false))
                .andReturn();

        List<String> setCookies = result.getResponse().getHeaders("Set-Cookie");
        long xsrfCount = setCookies.stream().filter(c -> c.startsWith("XSRF-TOKEN=")).count();
        long sessionCount = setCookies.stream().filter(c -> c.startsWith("JSESSIONID=")).count();
        assertThat(xsrfCount).isEqualTo(1);
        assertThat(sessionCount).isEqualTo(1);
    }

    @Test
    @DisplayName("POST /api/auth/login with invalid password returns 401 Unauthorized Problem Details")
    void shouldFailLoginWithInvalidCredentials() throws Exception {
        LoginRequest loginRequest = new LoginRequest("admin", "wrong_password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/unauthorized"))
                .andExpect(jsonPath("$.title").value("Unauthorized"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.detail").value("Invalid username or password."))
                .andExpect(jsonPath("$.instance").value("/api/auth/login"))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @Test
    @DisplayName("POST /api/auth/login with unknown username returns 401 Unauthorized Problem Details without leaking user existence")
    void shouldFailLoginWithUnknownUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("unknown_operator", "admin");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/unauthorized"))
                .andExpect(jsonPath("$.title").value("Unauthorized"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.detail").value("Invalid username or password."))
                .andExpect(jsonPath("$.instance").value("/api/auth/login"))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @Test
    @DisplayName("POST /api/auth/login with blank credentials returns 422 Unprocessable Entity with invalidParams")
    void shouldReturn422WhenLoginCredentialsAreBlank() throws Exception {
        LoginRequest loginRequest = new LoginRequest("", "");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/validation-error"))
                .andExpect(jsonPath("$.title").value("Validation Failed"))
                .andExpect(jsonPath("$.status").value(422))
                .andExpect(jsonPath("$.instance").value("/api/auth/login"))
                .andExpect(jsonPath("$.invalidParams", hasSize(2)))
                .andExpect(jsonPath("$.invalidParams[*].name", containsInAnyOrder("username", "password")));
    }

    @Test
    @DisplayName("GET /api/auth/me returns 200 OK when authenticated and 401 Unauthorized Problem Details when unauthenticated")
    void shouldGetMeWhenAuthenticatedAndFailWhenUnauthenticated() throws Exception {
        // 1. Unauthenticated request
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/unauthorized"))
                .andExpect(jsonPath("$.title").value("Unauthorized"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.instance").value("/api/auth/me"));

        // 2. Authenticate
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("admin", "admin"))))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        Cookie jsessionId = loginResult.getResponse().getCookie("JSESSIONID");

        // 3. Authenticated request
        mockMvc.perform(get("/api/auth/me")
                        .session(session)
                        .cookie(jsessionId))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("POST /api/auth/logout WITHOUT X-XSRF-TOKEN header is rejected with 403 Forbidden")
    void shouldRejectLogoutWithoutCsrfToken() throws Exception {
        // 1. Authenticate
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("admin", "admin"))))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        Cookie jsessionId = loginResult.getResponse().getCookie("JSESSIONID");
        Cookie xsrfCookie = loginResult.getResponse().getCookie("XSRF-TOKEN");

        // 2. Attempt logout WITHOUT X-XSRF-TOKEN header
        mockMvc.perform(post("/api/auth/logout")
                        .session(session)
                        .cookie(jsessionId, xsrfCookie))
                .andExpect(status().isForbidden())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/access-denied"))
                .andExpect(jsonPath("$.title").value("Access Denied"))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.detail").value("CSRF token is missing or invalid."));
    }

    @Test
    @DisplayName("POST /api/auth/logout WITH valid JSESSIONID and X-XSRF-TOKEN header returns 204 No Content and invalidates session")
    void shouldLogoutSuccessfullyWithCsrfTokenAndInvalidateSession() throws Exception {
        // 1. Authenticate
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("admin", "admin"))))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        Cookie jsessionId = loginResult.getResponse().getCookie("JSESSIONID");
        Cookie xsrfCookie = loginResult.getResponse().getCookie("XSRF-TOKEN");

        // 2. Logout with valid session, cookie, and matching X-XSRF-TOKEN header
        MvcResult logoutResult = mockMvc.perform(post("/api/auth/logout")
                        .session(session)
                        .cookie(jsessionId, xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfCookie.getValue()))
                .andExpect(status().isNoContent())
                .andExpect(cookie().maxAge("JSESSIONID", 0))
                .andExpect(cookie().maxAge("XSRF-TOKEN", 0))
                .andReturn();

        List<String> logoutCookies = logoutResult.getResponse().getHeaders("Set-Cookie");
        long logoutXsrfCount = logoutCookies.stream().filter(c -> c.startsWith("XSRF-TOKEN=")).count();
        long logoutSessionCount = logoutCookies.stream().filter(c -> c.startsWith("JSESSIONID=")).count();
        assertThat(logoutXsrfCount).isEqualTo(1);
        assertThat(logoutSessionCount).isEqualTo(1);

        // 3. Subsequent GET /api/auth/me with the invalidated session returns 401 Unauthorized
        mockMvc.perform(get("/api/auth/me")
                        .session(session)
                        .cookie(jsessionId))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/unauthorized"))
                .andExpect(jsonPath("$.title").value("Unauthorized"))
                .andExpect(jsonPath("$.status").value(401));
    }
}
