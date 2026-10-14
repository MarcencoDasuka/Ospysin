package com.ospysin.execution.sse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Transactional event listener ensuring SSE events are broadcast ONLY AFTER the DB transaction commits.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionSseEventListener {

    private final SessionSseHub sessionSseHub;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onSessionSseDomainEvent(SessionSseDomainEvent event) {
        log.debug("Received AFTER_COMMIT SSE domain event '{}' for session {}", event.eventName(), event.sessionId());
        sessionSseHub.broadcast(event.sessionId(), event.eventName(), event.data());
    }
}
