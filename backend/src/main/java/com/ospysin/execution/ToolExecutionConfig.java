package com.ospysin.execution;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Configuration for bounded asynchronous execution pool and scheduling.
 */
@Configuration
@EnableAsync
@EnableScheduling
public class ToolExecutionConfig {

    @Bean(name = "toolExecutionExecutor")
    public ThreadPoolTaskExecutor toolExecutionExecutor(
            @Value("${ospysin.execution.pool.core-size:4}") int coreSize,
            @Value("${ospysin.execution.pool.max-size:16}") int maxSize,
            @Value("${ospysin.execution.pool.queue-capacity:100}") int queueCapacity
    ) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(coreSize);
        executor.setMaxPoolSize(maxSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix("ospysin-worker-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }
}
