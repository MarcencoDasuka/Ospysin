package com.ospysin.execution.sse;

import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.shared.error.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.UUID;

/**
 * Controller exposing the Server-Sent Events stream for audit sessions.
 */
@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
public class SessionSseController {

    private final AuditSessionRepository auditSessionRepository;
    private final SessionSseHub sessionSseHub;

    @GetMapping(value = "/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamSessionEvents(@PathVariable("id") UUID id) {
        if (!auditSessionRepository.existsById(id)) {
            throw new ResourceNotFoundException("Session not found: " + id);
        }
        return sessionSseHub.subscribe(id);
    }
}
