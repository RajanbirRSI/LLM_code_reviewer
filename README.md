# 🤖 LLM Code Reviewer & PR Agent

An intelligent **AI-powered code reviewer** and **pull request (PR) agent** that leverages LLM models via [Ollama](https://ollama.com/) and GitHub Actions to **automatically review, score, and merge pull requests** with detailed, multi-dimensional feedback.

![GitHub Workflow](https://img.shields.io/github/actions/workflow/status/RajanbirRSI/LLM_code_reviewer/code_review.yml?label=Code%20Review%20Workflow&style=flat-square)
![License](https://img.shields.io/github/license/RajanbirRSI/LLM_code_reviewer?style=flat-square)

---

## 🔍 Overview

This system provides **consistent, objective code quality assessment** and automates PR handling using LLM/SLM models like `qwen2.5-coder:3b`, `mistral`, `phi3:mini`, and `llama3.2:1b`.

It evaluates changes across **7 critical code quality dimensions**, assigns a **score out of 100**, and automatically merges high-quality PRs.

---

## 🎯 Key Features

- ✅ **AI-Powered Code Review** using local LLMs (via [Ollama](https://ollama.com/))
- ⚙️ **GitHub Actions Integration**: Auto-triggers on PRs, pushes, or manual dispatch
- 📊 **Score-Based Merge Decisions**
- 🧠 **Detailed Review Feedback** via markdown comments
- 🔄 **Multi-Model Fallback** with SLMs for enhanced coverage

---

## 📐 Scoring Breakdown

| Dimension       | Weight (%) | Description                                                 |
|----------------|------------|-------------------------------------------------------------|
| 🧹 Code Quality | 25         | Readability, efficiency, standards compliance               |
| 🔐 Security     | 25         | Vulnerability check, access control, secure data handling   |
| ⚙️ Functionality| 20         | Logical correctness, edge cases, error handling             |
| 🧱 Maintainability | 15     | Modularity, extensibility, complexity management            |
| 📝 Documentation| 10         | Docstrings, code comments, API references                   |
| 🚀 Performance  | 3          | Runtime/memory complexity, resource usage                   |
| 🧪 Testing       | 2          | Test coverage and case quality                              |

---

## 🚀 Demo Walkthrough

### ✅ Step 1: Trigger Events

The workflow activates automatically on:

- 🔁 **Pull Requests** targeting the `main` branch
- 🚀 **Pushes** to feature branches
- 🔨 **Manual workflow dispatch** (via GitHub UI)

---

### 🤖 Step 2: AI-Powered Analysis

**Setup Time**: *~10–15 seconds*

- ✅ Code diff extraction and preprocessing
- ⚙️ Analysis using Ollama LLMs with fallbacks
- 📈 Scoring and comment generation per review dimension

#### 🔧 AI Models Used:

| Type   | Models Used                            |
|--------|----------------------------------------|
| LLM    | `qwen2.5-coder:3b`, `mistral`          |
| SLM    | `phi3:mini`, `llama3.2:1b`             |

---

## 🛠️ Technologies Used

- 🧠 **LLMs via Ollama**
- 🔧 **GitHub Actions Workflow**
- 🐍 **Python** backend logic
- 🛠️ **Git CLI** for diffing and branch handling
-  X **Self Hosted Server** for hosting ollama and running LLM models on ollama

---

