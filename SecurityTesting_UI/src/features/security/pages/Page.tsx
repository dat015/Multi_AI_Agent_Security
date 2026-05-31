/* eslint-disable @typescript-eslint/no-explicit-any */
// src/App.tsx
import React, { useState, useCallback, useRef, useEffect } from "react";

import { apiClient } from "../../../lib/axios";
import FileUploader from "../components/FileUploader";
import Controls from "../components/Controls";
import StatusBox from "../components/StatusBox";
import TestPlanList from "../components/TestPlanList";
import type {
  AnalysisResult,
  ConfigUploadResponse,
  TestPlanItem,
} from "../types";

type AppStatus = "idle" | "running" | "done" | "error";

export const SecurityTesterPage: React.FC = () => {
  // State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [phase, setPhase] = useState("phase2");
  const [maxIter, setMaxIter] = useState(5);
  const [configId, setConfigId] = useState("");
  const [status, setStatus] = useState<AppStatus>("idle");
  const [statusMessage, setStatusMessage] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [testPlan, setTestPlan] = useState<TestPlanItem[]>([]);
  const [endpointsFound, setEndpointsFound] = useState(0);

  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
    };
  }, []);

  // Helper to stop polling
  const stopPolling = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
  }, []);

  // Polling function
  const pollResult = useCallback(async () => {
    if (!sessionId) return;

    try {
      const result = (await apiClient.get(
        `/api/agent/result/${sessionId}`,
      )) as AnalysisResult;

      if (result.status === "done") {
        stopPolling();
        setStatus("done");
        setEndpointsFound(result.endpoints_found || 0);
        setTestPlan(result.test_plan || []);
        setStatusMessage(
          `Tìm thấy ${result.endpoints_found || 0} endpoint có nguy cơ. Sinh ${result.test_plan?.length || 0} test case.`,
        );
      } else if (result.status === "error") {
        stopPolling();
        setStatus("error");
        setStatusMessage(`Lỗi: ${result.error || "Không xác định"}`);
      }
      // status === 'running' -> continue polling
    } catch (error: any) {
      stopPolling();
      setStatus("error");
      setStatusMessage(`Mất kết nối khi polling: ${error.message}`);
    }
  }, [sessionId, stopPolling]);

  // Start analysis
  const handleRunAnalysis = useCallback(async () => {
    if (!selectedFile) {
      setStatus("error");
      setStatusMessage("Vui lòng chọn file OpenAPI trước khi chạy.");
      return;
    }

    // Reset state
    stopPolling();
    setStatus("running");
    setStatusMessage("Đang phân tích...");
    setTestPlan([]);
    setSessionId(null);
    setEndpointsFound(0);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = (await apiClient.post("/api/agent/analyze", formData, {
        params: {
          phase,
          max_iter: maxIter,
          config_id: configId || undefined,
        },
        headers: {
          "Content-Type": "multipart/form-data",
        },
      })) as { session_id: string };

      setSessionId(response.session_id);

      // Start polling
      if (pollingIntervalRef.current) clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = setInterval(pollResult, 3000);
    } catch (error: any) {
      setStatus("error");
      setStatusMessage(`Không thể kết nối server: ${error.message}`);
    }
  }, [selectedFile, phase, maxIter, configId, pollResult, stopPolling]);

  // Download template config
  const handleDownloadTemplate = useCallback(async () => {
    try {
      const data = await apiClient.get("/config/template");
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "config_template.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setStatusMessage("Đã tải template config thành công");
    } catch (error: any) {
      setStatus("error");
      setStatusMessage(`Không tải được template: ${error.message}`);
    }
  }, []);

  // Upload config file to server
  const handleUploadConfig = useCallback(async (file: File) => {
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = (await apiClient.post("/upload-config", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })) as ConfigUploadResponse;

      if (response.status === "ok" && response.config_id) {
        setConfigId(response.config_id);
        setStatusMessage(
          `Config upload thành công — id: ${response.config_id}`,
        );
      } else {
        setStatus("error");
        setStatusMessage(
          `Lỗi upload: ${response.message || response.error || "Không xác định"}`,
        );
      }
    } catch (error: any) {
      setStatus("error");
      setStatusMessage(`Lỗi khi upload config: ${error.message}`);
    }
  }, []);

  // Export config by ID
  const handleExportConfig = useCallback(async () => {
    if (!configId.trim()) {
      setStatus("error");
      setStatusMessage("Vui lòng nhập config_id để export");
      return;
    }

    try {
      const response = await apiClient.get(`/config/download/${configId}`, {
        responseType: "blob",
      });
      const blob = new Blob([response as unknown as BlobPart], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `config_${configId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setStatusMessage(`Đã export config ${configId}`);
    } catch (error: any) {
      setStatus("error");
      setStatusMessage(`Lỗi export config: ${error.message}`);
    }
  }, [configId]);

  // Download test plan
  const handleDownloadTestPlan = useCallback(async () => {
    if (!sessionId) return;

    try {
      const response = await apiClient.get(`/api/agent/download/${sessionId}`, {
        responseType: "blob",
      });
      const blob = new Blob([response as unknown as BlobPart], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `test_plan_${sessionId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (error: any) {
      setStatus("error");
      setStatusMessage(`Lỗi tải test plan: ${error.message}`);
    }
  }, [sessionId]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-950 text-gray-200">
      <div className="app-container">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
            🔐 API Security Tester
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Tự động kiểm thử bảo mật API theo OWASP API Top 10
          </p>
        </div>

        {/* Upload Zone */}
        <div className="mb-6 uploader">
          <FileUploader
            onFileSelect={setSelectedFile}
            selectedFile={selectedFile}
          />
        </div>

        {/* Controls */}
        <div className="controls-row">
          <div className="controls-left">
            <Controls
              phase={phase}
              onPhaseChange={setPhase}
              maxIter={maxIter}
              onMaxIterChange={setMaxIter}
              configId={configId}
              onConfigIdChange={setConfigId}
              onRunAnalysis={handleRunAnalysis}
              isRunning={status === "running"}
              isFileSelected={!!selectedFile}
              onDownloadTemplate={handleDownloadTemplate}
              onUploadConfig={handleUploadConfig}
              onExportConfig={handleExportConfig}
            />
          </div>
        </div>

        {/* Status Box */}
        <div className="status-box">
          <StatusBox status={status} message={statusMessage} />
        </div>

        {/* Test Plan Results */}
        <div className="test-plan">
          {(testPlan.length > 0 || status === "done") && (
            <TestPlanList
              testPlan={testPlan}
              onDownload={handleDownloadTestPlan}
              showDownloadButton={status === "done" && testPlan.length > 0}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default SecurityTesterPage;
