package com.ospysin.llm.client;

/**
 * Client interface for interacting with the local LLM cybersecurity advisor.
 */
public interface LlmClient {

    /**
     * Generates structured JSON commentary for a completed step in Comment Mode.
     *
     * @param systemPrompt the bounded system instructions
     * @param userPrompt   the bounded user context containing active step results
     * @return raw response string from the model (expected to contain JSON)
     */
    String generateCommentJson(String systemPrompt, String userPrompt);

    /**
     * Generates free-form conversational reply in Tactical Chat Mode.
     *
     * @param systemPrompt the system prompt with audit context
     * @param userPrompt   the sanitized operator message
     * @return free text reply from the model
     */
    String generateChatReply(String systemPrompt, String userPrompt);
}
