<div align="center">

# 🛡️ Multi AI Agent Security

**Hệ thống kiểm thử bảo mật API tự động dựa trên kiến trúc Multi-Agent AI**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![LangGraph](https://img.shields.io/badge/LangGraph-Orchestration-FF6F00?style=for-the-badge&logo=langchain&logoColor=white)](https://langchain.com)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-E44D26?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/API-Security/)

<br/>

> Một nền tảng kiểm thử bảo mật API thế hệ mới — nơi các AI Agent phối hợp nhau để **tự động trinh sát, lập kế hoạch, thực thi tấn công và phân tích lỗ hổng** theo chuẩn OWASP API Security Top 10.

</div>

---

## 📖 Mục lục

- [Giới thiệu](#-giới-thiệu)
- [Ý tưởng & Động lực](#-ý-tưởng--động-lực)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Các tính năng chính](#-các-tính-năng-chính)
- [Pipeline hoạt động](#-pipeline-hoạt-động)
- [OWASP API Top 10 Coverage](#-owasp-api-top-10-coverage)
- [Công nghệ sử dụng](#-công-nghệ-sử-dụng)
- [Cấu trúc dự án](#-cấu-trúc-dự-án)
- [Cài đặt & Chạy](#-cài-đặt--chạy)
- [Cấu hình](#-cấu-hình)
- [Giao diện người dùng](#-giao-diện-người-dùng)
- [Cách đóng góp](#-cách-đóng-góp)

---

## 🚀 Giới thiệu

**Multi AI Agent Security** là một hệ thống kiểm thử bảo mật API **hoàn toàn tự động**, được xây dựng trên nền tảng **Multi-Agent AI** và orchestrated bởi **LangGraph**. Thay vì phải viết test case thủ công, hệ thống tự động:

1. **Phân tích** tài liệu API (Swagger/OpenAPI) để xác định các điểm cuối (endpoints) tiềm năng có rủi ro bảo mật.
2. **Lên kế hoạch tấn công** thông minh theo từng loại lỗ hổng OWASP.
3. **Thực thi** các cuộc tấn công với nhiều vai trò người dùng (attacker, victim, admin).
4. **Phân tích kết quả** bằng thuật toán **Secure Chain-of-Verification (Secure-CoVe)** để phán quyết lỗ hổng.

---

## 💡 Ý tưởng & Động lực

### Vấn đề hiện tại

Kiểm thử bảo mật API truyền thống đối mặt với nhiều thách thức:

- ⏱️ **Tốn thời gian**: Viết test case thủ công cho mỗi endpoint mất nhiều giờ đến nhiều ngày.
- 🧠 **Đòi hỏi chuyên môn cao**: Cần hiểu sâu về OWASP, HTTP, Business Logic để thiết kế tấn công hiệu quả.
- 🔁 **Lặp lại & nhàm chán**: Các pattern tấn công cơ bản (BOLA, Broken Auth...) có thể được tự động hóa.
- 📊 **Phân tích chủ quan**: Con người dễ bỏ sót hoặc phán đoán sai khi phân tích lượng lớn HTTP logs.

### Giải pháp

Hệ thống **Multi AI Agent** phân chia công việc kiểm thử bảo mật thành các **agent chuyên biệt**, mỗi agent đảm nhiệm một nhiệm vụ cụ thể trong pipeline:

```
Swagger/OpenAPI Spec → [Recon Agent] → [Planning Agent] → [Execution Agent] → [Analyzer Agent] → Security Report
```

Phương pháp này mang lại:
- ✅ **Tự động hóa hoàn toàn** từ đầu vào là Swagger spec đến đầu ra là báo cáo lỗ hổng.
- ✅ **Khả năng mở rộng**: Thêm loại lỗ hổng mới chỉ cần thêm analyzer plugin.
- ✅ **Độ chính xác cao**: Secure-CoVe loại bỏ false positive bằng cách kết hợp deterministic filter + LLM reasoning.
- ✅ **Song song hóa**: LLM Scheduler thực thi nhiều tác vụ phân tích đồng thời.

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MULTI AI AGENT SECURITY                      │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    SecurityTesting_UI (React + TypeScript)   │   │
│  │  Dashboard │ Workflow Visualizer │ Security Results │ Config │   │
│  └────────────────────────────┬─────────────────────────────────┘   │
│                               │ HTTP / REST API                     │
│  ┌────────────────────────────▼─────────────────────────────────┐   │
│  │                    FastAPI Backend (ai-agent)                │   │
│  │                                                              │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │              LangGraph Orchestrator                  │   │   │
│  │  │                                                      │   │   │
│  │  │  [Recon] ──► [Planning] ──► [Execution] ──► [Analyzer]  │   │
│  │  │     │            │              │               │    │   │   │
│  │  │  Parse API    LLM-based     HTTP Client    Secure-CoVe  │   │
│  │  │  Swagger      Attack Plan   ThreadPool     3-Tier Eval  │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  │                                                              │   │
│  │  ┌────────────┐  ┌──────────────┐  ┌────────────────────┐   │   │
│  │  │ LLM Service│  │ Variable     │  │ OWASP Knowledge    │   │   │
│  │  │ (Groq/    │  │ Store        │  │ Base (owasp_kb.json)│   │   │
│  │  │  OpenAI/  │  │ (Context Mgmt│  │                    │   │   │
│  │  │  Ollama)  │  │  per role)   │  │                    │   │   │
│  │  └────────────┘  └──────────────┘  └────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Các tính năng chính

### 🤖 Multi-Agent Pipeline
| Agent | Vai trò | Công nghệ |
|-------|---------|-----------|
| **Recon Agent** | Phân tích Swagger/OpenAPI, xác định attack surface | LLM + OWASP KB |
| **Planning Agent** | Sinh test plan chi tiết cho từng loại lỗ hổng | LLM Structured Output |
| **Execution Agent** | Thực thi HTTP requests theo kịch bản tấn công | httpx + ThreadPoolExecutor |
| **Analyzer Agent** | Phân tích kết quả, phán quyết lỗ hổng | Secure-CoVe 3-Tier |
| **Reporting Agent** | Tổng hợp báo cáo cuối | LLM Summary |

### 🔬 Secure-CoVe Analyzer (Chain-of-Verification)
Thuật toán phán quyết 3 tầng độc đáo, loại bỏ false positive:

```
Tier 1: Deterministic Evidence Filter (không tốn token LLM)
    ↓ (nếu suspicious)
Tier 2: LLM Fact Extraction (trích xuất sự kiện khách quan)
    ↓
Tier 3: Weighted Predicate Scoring → 4-state verdict
    └── VULNERABLE | SUSPICIOUS | INCONCLUSIVE | SAFE
```

### 🔐 Role-Based Attack System
- **Attacker (_A)**: Người dùng thực hiện tấn công
- **Victim (_B)**: Chủ sở hữu tài nguyên bị nhắm mục tiêu
- **Admin (_Admin)**: Tài khoản có quyền cao

### ⚡ Parallel LLM Scheduler
- Hỗ trợ nhiều API keys đồng thời (Groq, OpenAI, Ollama)
- Concurrency per key có thể cấu hình
- Fail-soft mode: một key lỗi không dừng toàn bộ pipeline

### 📋 Config-Driven Testing
Upload file JSON config để định nghĩa:
- URL đích và thông tin xác thực
- Danh sách user roles (attacker, victim, admin)
- Đường dẫn RESTler output (grammar.json, dependencies.json)

---

## 🔄 Pipeline hoạt động

### Bước 1 — Recon (Trinh sát)
```
Swagger/OpenAPI Spec
    → Parse & Extract endpoints
    → Static Security Analysis (SecurityAnalyzer)
    → LLM Audit: xác định vuln_type có khả năng tồn tại
    → RESTler Dependency Graph: xác định thứ tự thực thi
    → Output: attack scenarios list
```

### Bước 2 — Planning (Lập kế hoạch)
```
Attack scenarios + Dependency graph
    → Build endpoint context (path/query/body schema)
    → LLM: sinh TestPlan có test_steps chi tiết
    → _sanitize_plan: chuẩn hóa placeholder {{xxx_A/B}}
    → Output: list TestPlan (setup + attack plans)
```

### Bước 3 — Execution (Thực thi)
```
TestPlans
    → Auth Manager: lấy token cho từng role
    → VariableStore: resolve placeholder động
    → Setup plans: chạy trước để tạo dữ liệu baseline
    → Attack plans: chạy sau bằng role attacker
    → Hỗ trợ Load Test: ThreadPool + rate limiting
    → Output: execution_results
```

### Bước 4 — Analysis (Phân tích)
```
execution_results
    → Tier 1: Deterministic filter (nhanh, không tốn token)
    → Tier 2: LLM fact extraction với Pydantic schema
    → Tier 3: Predicate scoring → confidence score
    → score_to_verdict: VULNERABLE / SUSPICIOUS / INCONCLUSIVE / SAFE
    → Output: final_report
```

---

## 🎯 OWASP API Top 10 Coverage

| ID | Tên lỗ hổng | CWE | Analyzer |
|----|------------|-----|----------|
| **API1** | BOLA / IDOR | CWE-639 | `BOLAAnalyzer` |
| **API2** | Broken Authentication | CWE-287 | `BrokenAuthAnalyzer` |
| **API3** | Mass Assignment | CWE-915 | `MassAssignmentAnalyzer` |
| **API4** | Unrestricted Resource Consumption | CWE-400 | `ResourceConsumptionAnalyzer` |
| **API5** | BFLA (Broken Function Level Auth) | CWE-285 | `BFLAAnalyzer` |
| **API7** | SSRF | CWE-918 | `SSRFAnalyzer` |
| **API8** | Security Misconfiguration | CWE-16, CWE-200 | `SecurityMisconfigAnalyzer` |
| **API9** | Improper Inventory Management | CWE-1059 | `InventoryAnalyzer` |
| **Generic** | Fallback / Custom | CWE-200 | `FallbackAnalyzer` |

---

## 🛠️ Công nghệ sử dụng

### Backend (`ai-agent/`)
| Thư viện | Phiên bản | Mục đích |
|----------|-----------|---------|
| **FastAPI** | 0.100+ | REST API server |
| **LangGraph** | latest | Agent orchestration & state management |
| **LangChain** | latest | LLM abstraction, structured output |
| **httpx** | latest | Async HTTP client cho execution |
| **Pydantic** | v2 | Schema validation & structured LLM output |
| **python-dotenv** | latest | Quản lý biến môi trường |

### LLM Providers được hỗ trợ
- 🚀 **Groq** (khuyến nghị): Tốc độ cao, hỗ trợ nhiều API keys song song
- 🤖 **OpenAI**: GPT-4, GPT-3.5 Turbo
- 🦙 **Ollama**: LLM local (LLaMA 3.1, Llama 3.3 70B)

### Frontend (`SecurityTesting_UI/`)
| Thư viện | Phiên bản | Mục đích |
|----------|-----------|---------|
| **React** | 18 | UI framework |
| **TypeScript** | 5.0 | Type safety |
| **Vite** | 5.0 | Build tool & dev server |
| **TailwindCSS** | 3.x | Styling |
| **Recharts** | latest | Biểu đồ kết quả bảo mật |
| **Lucide React** | latest | Icon library |
| **Axios** | latest | HTTP client |

---

## 📁 Cấu trúc dự án

```
Multi AI Agent Security/
│
├── 📁 ai-agent/                    # Backend FastAPI + AI Agents
│   ├── 📁 app/
│   │   ├── 📁 agents/              # Các AI Agent
│   │   │   ├── recon_agent.py      # Agent trinh sát API
│   │   │   ├── planning_agent.py   # Agent lập kế hoạch tấn công
│   │   │   ├── execution_agent.py  # Agent thực thi HTTP
│   │   │   ├── analyzer_agent.py   # Agent phân tích (Secure-CoVe)
│   │   │   └── reporting_agent.py  # Agent tổng hợp báo cáo
│   │   │
│   │   ├── 📁 core/                # Module lõi
│   │   │   ├── orchestrator.py     # LangGraph workflow builder
│   │   │   ├── state.py            # Shared state schema
│   │   │   ├── auth_manager.py     # Quản lý xác thực
│   │   │   ├── credential_store.py # Lưu trữ thông tin xác thực
│   │   │   ├── restler_parser.py   # Parse RESTler dependency graph
│   │   │   ├── dependency_resolver.py # Giải quyết phụ thuộc API
│   │   │   ├── constants.py        # Hằng số & system prompts
│   │   │   └── config.py           # Cấu hình & biến môi trường
│   │   │
│   │   ├── 📁 services/            # Services
│   │   │   ├── llm_service.py      # LLM abstraction layer
│   │   │   └── llm_scheduler.py    # Parallel LLM task scheduler
│   │   │
│   │   ├── 📁 security/            # Security analysis
│   │   │   └── security_analyzer.py # Static threat analysis
│   │   │
│   │   ├── 📁 modules/             # Parsers & extractors
│   │   │   └── parser/
│   │   │       ├── swagger_parser.py   # Parse Swagger/OpenAPI
│   │   │       └── swagger_extractor.py
│   │   │
│   │   ├── 📁 controllers/         # API endpoints
│   │   │   └── agent_controller.py
│   │   │
│   │   ├── 📁 validator/           # Input validation
│   │   │   └── config_validator.py
│   │   │
│   │   └── main.py                 # FastAPI app entry point
│   │
│   ├── 📁 knowledge/               # OWASP Knowledge Base
│   │   └── owasp_kb.json           # OWASP API Top 10 definitions
│   │
│   ├── 📁 Compile/                 # RESTler output (grammar, deps)
│   ├── 📁 swagger/                 # Swagger specs đầu vào
│   ├── 📁 outputs/                 # Kết quả thực thi
│   └── .env                        # Biến môi trường
│
└── 📁 SecurityTesting_UI/          # Frontend React
    ├── 📁 src/
    │   ├── 📁 features/
    │   │   ├── dashboard/          # Trang tổng quan
    │   │   ├── security/           # Trang kết quả bảo mật
    │   │   └── workFlow/           # Visualizer pipeline
    │   │
    │   ├── 📁 components/          # Shared components
    │   ├── 📁 layouts/             # Layout components
    │   ├── 📁 routes/              # React routing
    │   └── 📁 types/               # TypeScript types
    │
    └── package.json
```

---

## ⚙️ Cài đặt & Chạy

### Yêu cầu hệ thống
- Python **3.10+**
- Node.js **18+**
- Ít nhất 1 LLM API Key (Groq được khuyến nghị vì miễn phí và nhanh)

### 1. Clone dự án

```bash
git clone <repository-url>
cd "Multi AI Agent Security"
```

### 2. Cài đặt Backend

```bash
cd ai-agent

# Tạo virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate # Linux/macOS

# Cài đặt dependencies
pip install fastapi uvicorn langgraph langchain langchain-openai \
            langchain-groq httpx pydantic python-dotenv PyYAML
```

### 3. Cấu hình môi trường Backend

Tạo file `.env` trong thư mục `ai-agent/`:

```env
# LLM Provider (groq | openai | ollama)
LLM_PROVIDER=groq

# Groq API Keys (hỗ trợ nhiều key để tăng throughput)
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
GROQ_API_KEY1=gsk_yyyyyyyyyyyyyyyyyyyy
GROQ_API_KEY2=gsk_zzzzzzzzzzzzzzzzzzzz

# Model names
GPT_OOS_20B=llama-3.3-70b-versatile
LLAMA_3_3_70B=llama-3.3-70b-versatile

# LLM Server URL (để trống nếu dùng Groq mặc định)
URL_LLM=https://api.groq.com/openai/v1

# Parallel execution settings
LLM_PARALLEL_KEYS=3
LLM_CONCURRENCY_PER_KEY=2
LLM_MAX_RETRIES=5

# Optional: OpenAI
# OPENAI_API_KEY=sk-xxxx

# Optional: Ollama (local)
# OLLAMA_BASE_URL=http://localhost:11434/v1
# OLLAMA_MODEL=llama3.1
```

### 4. Khởi chạy Backend

```bash
cd ai-agent
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend sẽ chạy tại: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`
- API Endpoint: `http://localhost:8000/api/agent/`

### 5. Cài đặt & Chạy Frontend

```bash
cd SecurityTesting_UI

# Cài đặt dependencies
npm install

# Chạy development server
npm run dev
```

Frontend sẽ chạy tại: `http://localhost:5173`

---

## 📝 Cấu hình

### File Config JSON (Upload qua UI)

```json
{
  "target": {
    "base_url": "http://your-api-server.com"
  },
  "users": [
    {
      "role": "attacker",
      "email": "attacker@example.com",
      "password": "password123"
    },
    {
      "role": "victim",
      "email": "victim@example.com",
      "password": "password456"
    },
    {
      "role": "admin",
      "email": "admin@example.com",
      "password": "adminpass"
    }
  ],
  "auth": {
    "login_endpoint": "/api/auth/login",
    "token_field": "access_token",
    "method": "POST"
  },
  "restler_compile_path": "Compile"
}
```

### Swagger/OpenAPI Spec
- Hỗ trợ format: **JSON** và **YAML**
- Phiên bản: **OpenAPI 2.0 (Swagger)** và **OpenAPI 3.x**
- Upload trực tiếp qua giao diện UI

---

## 🖥️ Giao diện người dùng

### Trang Dashboard
- Tổng quan tình trạng bảo mật hệ thống
- Biểu đồ phân phối lỗ hổng theo loại OWASP
- Thống kê số lượng endpoint được kiểm tra

### Trang Security Testing
- Upload Swagger spec và file config
- Theo dõi tiến trình pipeline theo thời gian thực
- Xem chi tiết kết quả từng endpoint
- Phán quyết theo 4 cấp độ: `VULNERABLE` | `SUSPICIOUS` | `INCONCLUSIVE` | `SAFE`
- Mức độ nghiêm trọng: `Critical` | `High` | `Medium` | `Low` | `Safe`

### Trang Workflow Visualizer
- Trực quan hóa dependency graph giữa các API endpoint
- Hiển thị thứ tự thực thi được tính toán tự động

---

## 🔧 Các chế độ chạy Pipeline

Hệ thống hỗ trợ 4 chế độ thực thi qua `orchestrator.py`:

| Chế độ | Mô tả |
|--------|-------|
| `phase1` | Chỉ chạy Recon → Planning (không thực thi) |
| `phase2` | Recon → Planning → Execution → Analyzer |
| `exec_only` | Chỉ chạy Execution từ test plan có sẵn |
| `full` | Pipeline đầy đủ với vòng lặp và Reporting |

---

## 🤝 Cách đóng góp

1. Fork repository này
2. Tạo branch mới: `git checkout -b feature/ten-tinh-nang`
3. Commit changes: `git commit -m 'feat: thêm tính năng X'`
4. Push lên branch: `git push origin feature/ten-tinh-nang`
5. Tạo Pull Request

### Thêm Analyzer Plugin mới

Để thêm coverage cho lỗ hổng mới, chỉ cần tạo class kế thừa `BaseVulnerabilityAnalyzer` trong `analyzer_agent.py`:

```python
class MyNewAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type  = "API6"
    cwe_info   = "CWE-XXX: Description"
    ground_truth = "Mô tả lỗ hổng..."

    def get_extraction_schema(self): return MyNewFacts
    def get_extraction_prompt(self): return "Prompt để LLM trích xuất facts..."
    def evaluate_predicates(self, facts, evidence): return {"P1": ..., "P2": ...}
    def calculate_confidence(self, predicates): return sum(...)
```

Sau đó đăng ký trong `_PLUGIN_MAP`:
```python
_PLUGIN_MAP["API6"] = MyNewAnalyzer
```

---

## 📄 License

Dự án này được phát triển cho mục đích nghiên cứu và học thuật về **bảo mật API** và **Multi-Agent AI Systems**.

> ⚠️ **Cảnh báo**: Chỉ sử dụng công cụ này trên các hệ thống mà bạn **có quyền** kiểm thử. Việc sử dụng trái phép để tấn công hệ thống của người khác là vi phạm pháp luật.

---

<div align="center">

**Được xây dựng với ❤️ bằng Python, FastAPI, LangGraph và React**

</div>
