package com.ospysin.tools;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST controller exposing the authoritative tool catalog.
 */
@RestController
@RequestMapping("/api/tools")
@RequiredArgsConstructor
public class ToolCatalogController {

    private final ToolCatalogRegistry toolCatalogRegistry;

    @GetMapping
    public ResponseEntity<List<ToolMetadata>> listTools() {
        return ResponseEntity.ok(toolCatalogRegistry.getAllTools());
    }
}
