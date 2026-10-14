package com.ospysin.execution.sse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe SSE hub managing per-session SseEmitter subscriptions with lifecycle callbacks and broadcast capabilities.
 */
@Slf4j
@Component
public class SessionSseHub {

    public static final long SSE_TIMEOUT_MS = 30 * 60 * 1000L; // 30 minutes

    private final ConcurrentHashMap<UUID, CopyOnWriteArrayList<SseEmitter>> activeEmitters = new ConcurrentHashMap<>();

    /**
     * Subscribes a client to SSE events for the given sessionId.
     *
     * @param sessionId the audit session identifier
     * @return the configured SseEmitter
     */
    public SseEmitter subscribe(UUID sessionId) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);

        emitter.onCompletion(() -> removeEmitter(sessionId, emitter));
        emitter.onTimeout(() -> {
            log.debug("SSE emitter timed out for session {}", sessionId);
            removeEmitter(sessionId, emitter);
        });
        emitter.onError(ex -> {
            log.debug("SSE emitter error for session {}: {}", sessionId, ex.getMessage());
            removeEmitter(sessionId, emitter);
        });

        activeEmitters.computeIfAbsent(sessionId, k -> new CopyOnWriteArrayList<>()).add(emitter);
        log.debug("Registered SSE emitter for session {}. Total active for session: {}", sessionId, getActiveEmitterCount(sessionId));

        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data(Map.of("sessionId", sessionId.toString()), MediaType.APPLICATION_JSON));
        } catch (IOException | IllegalStateException e) {
            log.warn("Failed to send initial SSE connected event for session {}", sessionId);
            removeEmitter(sessionId, emitter);
        }

        return emitter;
    }

    /**
     * Broadcasts an event to all active emitters subscribed to sessionId.
     *
     * @param sessionId the audit session identifier
     * @param eventName the canonical SSE event name
     * @param data the payload data
     */
    public void broadcast(UUID sessionId, String eventName, Object data) {
        List<SseEmitter> emitters = activeEmitters.get(sessionId);
        if (emitters == null || emitters.isEmpty()) {
            log.trace("No active SSE subscribers for session {}, event {}", sessionId, eventName);
            return;
        }

        log.debug("Broadcasting SSE event '{}' to {} subscribers for session {}", eventName, emitters.size(), sessionId);
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name(eventName)
                        .data(data, MediaType.APPLICATION_JSON));
            } catch (Exception ex) {
                log.debug("Error delivering SSE event '{}' to emitter for session {}: {}", eventName, sessionId, ex.getMessage());
                removeEmitter(sessionId, emitter);
            }
        }
    }

    /**
     * Deterministically removes an emitter and prunes the session entry if empty.
     */
    public void removeEmitter(UUID sessionId, SseEmitter emitter) {
        if (sessionId == null || emitter == null) {
            return;
        }
        activeEmitters.computeIfPresent(sessionId, (k, list) -> {
            list.remove(emitter);
            return list.isEmpty() ? null : list;
        });
        log.trace("Removed SSE emitter for session {}. Remaining: {}", sessionId, getActiveEmitterCount(sessionId));
    }

    /**
     * @return current count of active emitters for a session
     */
    public int getActiveEmitterCount(UUID sessionId) {
        List<SseEmitter> list = activeEmitters.get(sessionId);
        return list != null ? list.size() : 0;
    }

    /**
     * Clears all active emitters (useful for testing and graceful shutdown).
     */
    public void clearAll() {
        activeEmitters.clear();
    }
}
