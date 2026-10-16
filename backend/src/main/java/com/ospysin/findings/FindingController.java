package com.ospysin.findings;

import com.ospysin.findings.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/sessions/{id}")
@RequiredArgsConstructor
public class FindingController {

    private final FindingTxService findingTxService;
    private final SessionReportService sessionReportService;

    @GetMapping("/observations")
    public List<SessionObservationResponse> getObservations(@PathVariable("id") UUID id) {
        return findingTxService.getSessionObservations(id);
    }

    @GetMapping("/findings")
    public List<FindingResponse> getFindings(@PathVariable("id") UUID id) {
        return findingTxService.getFindings(id);
    }

    @PostMapping("/findings")
    @ResponseStatus(HttpStatus.CREATED)
    public FindingResponse createFinding(
            @PathVariable("id") UUID id,
            @Valid @RequestBody CreateFindingRequest request
    ) {
        return findingTxService.createFinding(id, request);
    }

    @PatchMapping("/findings/{findingId}")
    public FindingResponse updateFinding(
            @PathVariable("id") UUID id,
            @PathVariable("findingId") UUID findingId,
            @Valid @RequestBody UpdateFindingRequest request
    ) {
        return findingTxService.updateFinding(id, findingId, request);
    }

    @PostMapping("/findings/{findingId}/evidence")
    @ResponseStatus(HttpStatus.CREATED)
    public EvidenceResponse attachEvidence(
            @PathVariable("id") UUID id,
            @PathVariable("findingId") UUID findingId,
            @Valid @RequestBody CreateEvidenceRequest request
    ) {
        return findingTxService.attachEvidence(id, findingId, request);
    }

    @GetMapping(value = "/report", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> getReportHtml(@PathVariable("id") UUID id) {
        String html = sessionReportService.generateStandaloneHtmlReport(id);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/html;charset=UTF-8"))
                .body(html);
    }
}
