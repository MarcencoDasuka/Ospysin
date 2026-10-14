package com.ospysin.execution.sse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SessionSseHubTest {

    private SessionSseHub sseHub;

    @BeforeEach
    void setUp() {
        sseHub = new SessionSseHub();
    }

    @Test
    @DisplayName("subscribe registers emitter and increments active emitter count")
    void subscribeRegistersEmitter() {
        UUID sessionId = UUID.randomUUID();
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(0);

        SseEmitter emitter1 = sseHub.subscribe(sessionId);
        assertThat(emitter1).isNotNull();
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(1);

        SseEmitter emitter2 = sseHub.subscribe(sessionId);
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(2);

        // Broadcast should succeed without errors
        sseHub.broadcast(sessionId, "step_queued", Map.of("toolId", "http_headers"));
    }

    @Test
    @DisplayName("removeEmitter cleans up emitter and prunes session map entry when empty")
    void removeEmitterCleansUp() {
        UUID sessionId = UUID.randomUUID();
        SseEmitter emitter1 = sseHub.subscribe(sessionId);
        SseEmitter emitter2 = sseHub.subscribe(sessionId);
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(2);

        sseHub.removeEmitter(sessionId, emitter1);
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(1);

        sseHub.removeEmitter(sessionId, emitter2);
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(0);

        // Safe to call with non-registered or null
        sseHub.removeEmitter(sessionId, emitter1);
        sseHub.removeEmitter(null, null);
    }

    @Test
    @DisplayName("broadcast to session without active emitters is a safe no-op")
    void broadcastWithoutSubscribers() {
        UUID sessionId = UUID.randomUUID();
        sseHub.broadcast(sessionId, "test_event", Map.of("key", "val"));
        assertThat(sseHub.getActiveEmitterCount(sessionId)).isEqualTo(0);
    }

    @Test
    @DisplayName("SessionSseEventListener delegates AFTER_COMMIT event to SessionSseHub broadcast")
    void eventListenerDelegatesToHub() {
        SessionSseHub mockHub = mock(SessionSseHub.class);
        SessionSseEventListener listener = new SessionSseEventListener(mockHub);

        UUID sessionId = UUID.randomUUID();
        Map<String, Object> data = Map.of("executionId", UUID.randomUUID().toString(), "status", "RUNNING");
        SessionSseDomainEvent event = new SessionSseDomainEvent(sessionId, "step_started", data);

        listener.onSessionSseDomainEvent(event);

        verify(mockHub).broadcast(sessionId, "step_started", data);
    }
}
