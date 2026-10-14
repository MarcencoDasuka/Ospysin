package com.ospysin.sessions;

import com.ospysin.sessions.dto.CreateSessionRequest;
import com.ospysin.sessions.dto.SessionPageResponse;
import com.ospysin.sessions.dto.SessionResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
public class AuditSessionController {

    private final AuditSessionService auditSessionService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SessionResponse createSession(@Valid @RequestBody CreateSessionRequest request) {
        return auditSessionService.createSession(request);
    }

    @GetMapping
    public SessionPageResponse getSessions(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return auditSessionService.getSessions(page, size);
    }

    @GetMapping("/{id}")
    public SessionResponse getSession(@PathVariable UUID id) {
        return auditSessionService.getSession(id);
    }

    @PostMapping("/{id}/complete")
    public SessionResponse completeSession(@PathVariable UUID id) {
        return auditSessionService.completeSession(id);
    }

    @PostMapping("/{id}/abort")
    public SessionResponse abortSession(@PathVariable UUID id) {
        return auditSessionService.abortSession(id);
    }
}
