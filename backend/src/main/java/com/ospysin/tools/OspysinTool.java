package com.ospysin.tools;

import com.ospysin.shared.error.ValidationException;

import java.util.Map;

/**
 * Pluggable SPI contract for Ospysin inspection and reconnaissance tools.
 */
public interface OspysinTool {

    /**
     * @return the unique tool identifier matching ToolMetadata.id
     */
    String getToolId();

    /**
     * Validates input parameters against the tool's schema.
     *
     * @param params the tool input parameters
     * @throws ValidationException if input parameters violate the schema
     */
    void validateParams(Map<String, Object> params) throws ValidationException;

    /**
     * Executes the deterministic tool probe or analytical logic outside any database transaction.
     *
     * @param context the tool execution context
     * @return the structured tool execution outcome
     * @throws Exception if tool execution encounters an error
     */
    ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception;
}
