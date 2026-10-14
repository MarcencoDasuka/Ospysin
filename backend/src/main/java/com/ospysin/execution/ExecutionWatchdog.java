package com.ospysin.execution;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Watchdog periodically detecting and reclaiming expired leases from stalled or dead workers,
 * and draining orphaned pending tasks.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ExecutionWatchdog {

    private final ToolExecutionTxService toolExecutionTxService;
    private final ToolExecutionWorker toolExecutionWorker;

    /**
     * Reclaims expired leases. Runs on fixed delay and is invokable directly in tests.
     *
     * @return number of reclaimed executions
     */
    @Scheduled(fixedDelayString = "${ospysin.execution.watchdog-interval-ms:5000}")
    public int reclaimExpiredLeases() {
        int reclaimed = toolExecutionTxService.reclaimExpiredLeases();
        if (reclaimed > 0) {
            log.info("ExecutionWatchdog reclaimed {} expired execution lease(s)", reclaimed);
        }
        if (toolExecutionWorker.isAutoDispatchEnabled()) {
            int drained = toolExecutionWorker.drainPendingQueue();
            if (drained > 0) {
                log.info("ExecutionWatchdog drained {} pending execution(s)", drained);
            }
        }
        return reclaimed;
    }
}
