
import { FileUpload } from "../components/FileUpload";
import { ControlsBar } from "../components/ControlsBar";
import { StatusCard } from "../components/StatusCard";
import { TestPlanList } from "../components/TestPlanList";
import type { PollResponse, TestCase } from "../types";
import { useEffect, useRef, useState, type ChangeEvent, type DragEvent } from "react";
import { apiClient } from "../../../lib/axios";

type StatusType = "idle" | "running" | "done" | "error";

export const SecurityTesterPage: React.FC = () => {
  // UI State
  const [file, setFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  // Form State
  const [phase, setPhase] = useState("phase1");
  const [maxIter, setMaxIter] = useState(5);
  const [configId, setConfigId] = useState("");

  // Process State
  const [status, setStatus] = useState<StatusType>("idle");
  const [message, setMessage] = useState("");
  const [testPlan, setTestPlan] = useState<TestCase[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);

  // Refs for hidden inputs
  const fileInputRef = useRef<HTMLInputElement>(null);
  const configInputRef = useRef<HTMLInputElement>(null);

  // --- Handlers: Drag & Drop ---
  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => setIsDragOver(false);

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  // --- Handlers: API Interactions ---
  const downloadTemplate = async () => {
    try {
      const res = await apiClient.get("/config/template");
      const data = res.data;
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "config_template.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setStatus("error");
      setMessage("Không tải được mẫu: " + err.message);
    }
  };

  const uploadConfig = async (e: ChangeEvent<HTMLInputElement>) => {
    const uploadedFile = e.target.files?.[0];
    if (!uploadedFile) return;

    setStatus("running");
    setMessage("Đang upload cấu hình...");

    const fd = new FormData();
    fd.append("file", uploadedFile);

    try {
      const res = await apiClient.post("/upload-config", fd);
      const data = res.data;

      if (res.status === 200 && data.status === "ok") {
        setStatus("done");
        setMessage(`Config upload thành công — id: ${data.config_id}`);
        setConfigId(data.config_id);
      } else {
        setStatus("error");
        setMessage("Lỗi khi upload: " + (data.message || data.error));
      }
    } catch (err: any) {
      setStatus("error");
      setMessage("Không kết nối được server: " + err.message);
    }
    // Reset input để có thể chọn lại cùng 1 file
    if (configInputRef.current) configInputRef.current.value = "";
  };

  const runAnalysis = async () => {
    if (!file) return;

    setStatus("running");
    setMessage("Đang phân tích...");
    setTestPlan([]);
    setSessionId(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await apiClient.post(
        `/api/agent/analyze?phase=${phase}&max_iter=${maxIter}`,
        formData
      );
      setSessionId(res.data.session_id);
    } catch (err: any) {
      setStatus("error");
      setMessage("Không kết nối được server: " + err.message);
    }
  };

  // --- Effect: Polling Logic ---
  useEffect(() => {
    let intervalId: NodeJS.Timeout;

    const poll = async () => {
      if (!sessionId || status !== "running") return;
      try {
        const res = await apiClient.get(`/api/agent/result/${sessionId}`);
        const data: PollResponse = res.data;

        if (data.status === "done") {
          setStatus("done");
          setMessage(
            `Tìm thấy ${data.endpoints_found} endpoint có nguy cơ. Sinh ${data.test_plan?.length || 0} test case.`,
          );
          setTestPlan(data.test_plan || []);
        } else if (data.status === "error") {
          setStatus("error");
          setMessage("Lỗi: " + data.error);
        }
      } catch (err) {
        setStatus("error");
        setMessage("Mất kết nối khi polling");
      }
    };

    if (status === "running" && sessionId) {
      intervalId = setInterval(poll, 3000);
    }

    return () => clearInterval(intervalId); // Cleanup interval khi unmount hoặc đổi state
  }, [sessionId, status]);

  return (
    <div className="min-h-screen bg-[#0f1117] text-[#e0e0e0] font-sans p-5 md:p-10">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-medium text-white mb-2">
          🔐 API Security Tester
        </h1>
        <p className="text-[#9aa3b2] text-sm mb-8">
          Tự động kiểm thử bảo mật API theo OWASP API Top 10
        </p>

        <FileUpload
          file={file}
          isDragOver={isDragOver}
          fileInputRef={fileInputRef}
          onClick={() => fileInputRef.current?.click()}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onFileChange={(f) => setFile(f)}
        />

        <ControlsBar
          phase={phase}
          setPhase={setPhase}
          maxIter={maxIter}
          setMaxIter={setMaxIter}
          runAnalysis={runAnalysis}
          downloadTemplate={downloadTemplate}
          configId={configId}
          setConfigId={setConfigId}
          configInputRef={configInputRef}
          onConfigUploadClick={() => configInputRef.current?.click()}
          disabledRun={!file || status === "running"}
        />

        <StatusCard status={status} message={message} />

        {status === "done" && (
          <TestPlanList testPlan={testPlan} sessionId={sessionId} />
        )}
      </div>
    </div>
  );
};
