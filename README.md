# LLM Crawlers IOCs for Threat Hunting and CTI

**LLM User-Agents + IP Ranges**  
**Purpose:** Enable proactive detection, blocking, and hunting of LLM-driven reconnaissance (AI-orchestrated cyber operations).

---

## Overview

This repository provides a **high-fidelity, machine-readable threat intelligence feed** focused on **Large Language Model (LLM) crawlers and autonomous agents** used for web scraping, data ingestion, and reconnaissance.  

All indicators are **verified against official vendor documentation** (OpenAI, Anthropic, Google, Perplexity, Mistral, etc.) and enriched with observed behavioral patterns from public logs analysis.

---

## Feed Contents

| File | Format | Use Case |
|------|--------|---------|
| [`user-agents_llm.json`](./user-agents_llm.json) | JSON | SIEM correlation, WAF rules, EDR telemetry |
| [`ip-ranges_llm.json`](./ip-ranges_llm.json) | JSON | Firewall ACLs, IDS/IPS, Geo-IP blocking |
| [`regex_llm.txt`](./regex_llm.txt) | Plaintext | Regex-based detection (Nginx, Suricata, Python) |

---

## Threat Intelligence Value

| Indicator Type | Coverage                     | TTP Mapping (MITRE ATT&CK)            |
|----------------|------------------------------|---------------------------------------|
| IOC            | User-Agent strings        | T1595.002 – Active Scanning           |
| IOC            | CIDR blocks / IPs         | T1046 – Network Service Discovery     |

> Key Insight: LLM crawlers often operate in unsupervised reconnaissance mode, leveraging default agent configurations (e.g., ClaudeBot auto-following internal links). This enables autonomous attack surface mapping, a core phase in AI-driven campaigns.

---

## LLM User-Agents  

| Category            | User-Agent String        | Description                                      |
|---------------------|--------------------------|--------------------------------------------------|
| OpenAI / ChatGPT    | GPTBot                   | Crawls public web for model training (OpenAI).   |
| OpenAI / ChatGPT    | OAI-SearchBot            | Powers real-time search in ChatGPT.              |
| OpenAI / ChatGPT    | ChatGPT-Browser          | Browser automation for plugin actions.           |
| OpenAI / ChatGPT    | ChatGPT-User             | User-triggered web navigation (v1).              |
| OpenAI / ChatGPT    | ChatGPT-User-v2          | Updated user-triggered browsing (v2).            |
| Anthropic / Claude  | ClaudeBot                | Autonomous web crawling for grounding.           |
| Anthropic / Claude  | claude-web               | Web interaction in Claude responses.             |
| Anthropic / Claude  | Anthropic-Claude         | Internal agent for web tasks.                    |
| Anthropic / Claude  | anthropic-ai             | Legacy training crawler.                         |
| Google / Gemini     | Gemini-Ai                | Gemini app web browsing.                         |
| Google / Gemini     | Gemini-Deep-Research     | Deep Research assistant crawler.                 |
| Google / Gemini     | Google-CloudVertexBot    | Vertex AI grounding agent.                       |
| Google / Gemini     | Google-Extended          | Extended crawling for Gemini models.             |
| Google / Gemini     | Google-NotebookLM        | NotebookLM source fetching.                      |
| Google / Gemini     | Bard-Ai                  | Legacy Bard web agent.                           |
| xAI / Grok          | xAI-Bot                  | Grok real-time web access (via X).               |
| Perplexity          | PerplexityBot            | Periodic indexing for answers.                   |
| Perplexity          | Perplexity-User          | User-initiated real-time browsing.               |
| Perplexity          | Perplexity-Stealth       | Stealth mode (mimics Chrome).                    |
| Cohere              | Cohere-Ai                | Cohere model grounding.                          |
| Cohere              | Cohere-Command           | Command R+ web agent.                            |
| Cohere              | cohere-ai                | Legacy Cohere crawler.                           |
| Mistral             | MistralAI-User           | Le Chat web fetching.                            |
| DeepSeek            | DeepseekBot              | DeepSeek real-time search.                       |
| Hugging Face        | HuggingFace-Bot          | Model training & demo scraping.                  |
| Groq                | Groq-Bot                 | GroqChat web context.                            |
| Replicate           | Replicate-Bot            | Replicate demo & training data.                  |
| RunPod              | RunPod-Bot               | RunPod-hosted model crawler.                     |
| Together AI         | Together-Bot             | Together AI playground scraping.                 |
| Other AI/LLMs       | AI2Bot                   | Allen Institute research crawler.                |
| Other AI/LLMs       | Amazonbot                | Amazon Titan model training.                     |
| Other AI/LLMs       | Andibot                  | Andi search AI crawler.                          |
| Other AI/LLMs       | Brightbot                | Bright Data AI scraping.                         |
| Other AI/LLMs       | Character-AI             | Character.AI context gathering.                  |
| Other AI/LLMs       | Cotoyogi                 | Japanese AI research bot.                        |
| Other AI/LLMs       | Crawlspace               | AI dev tool crawler.                             |
| Other AI/LLMs       | Devin                    | Cognition Labs AI agent.                         |
| Other AI/LLMs       | FirecrawlAgent           | Firecrawl.dev web scraper.                       |
| Other AI/LLMs       | IbouBot                  | Ibou AI search engine.                           |
| Other AI/LLMs       | ImagesiftBot             | Image-focused AI training.                       |
| Other AI/LLMs       | Kangaroo Bot             | Australian AI research crawler.                  |
| Other AI/LLMs       | PanguBot                 | Huawei Pangu model crawler.                      |
| Other AI/LLMs       | TerraCotta               | Ceramic AI data collector.                       |
| Other AI/LLMs       | TimpiBot                 | Timpi.io AI agent.                               |
| Other AI/LLMs       | Webzio-Extended          | Webzio AI extended crawler.                      |
| Other AI/LLMs       | bigsur.ai                | BigSur AI research bot.                          |

---

## IP ranges (official)

| Vendor | Agent | Details |
|--------|-------|---------|
| OpenAI | GPTBot | [`https://openai.com/gptbot.json`](https://openai.com/gptbot.json) |
| OpenAI | ChatGPT-User | [`https://openai.com/chatgpt-user.json`](https://openai.com/chatgpt-user.json) |
| OpenAI | OAI-SearchBot | [`https://openai.com/searchbot.json`](https://openai.com/searchbot.json) |
| OpenAI | ChatGPT-Actions | [`https://openai.com/chatgpt-actions.json`](https://openai.com/chatgpt-actions.json) |
| Anthropic | ClaudeBot | [`https://docs.claude.com/es/api/ip-addresses`](https://docs.claude.com/es/api/ip-addresses) |
| Perplexity | PerplexityBot | [`https://www.perplexity.com/perplexitybot.json`](https://www.perplexity.com/perplexitybot.json) |
| Perplexity | Perplexity-User | [`https://www.perplexity.ai/perplexity-user.json`](https://www.perplexity.ai/perplexity-user.json) |
| Mistral | MistralAI-User | [`https://mistral.ai/mistralai-user-ips.json`](https://mistral.ai/mistralai-user-ips.json) |
| Amazon | Amazonbot | [`https://developer.amazon.com/amazonbot/live-ip-addresses/`](https://developer.amazon.com/amazonbot/live-ip-addresses/) |
| Google | Gemini-Extended |  No public IPs |
| Others | xAI-Bot | No public IPs |
| Others | DeepseekBot | No public IPs |
| Others | Groq-Bot | No public IPs |
| Others | HuggingFace-Bot | No public IPs |
| Others | Replicate-Bot | No public IPs |
| Others | RunPod-Bot | No public IPs |
| Others | Together-Bot | No public IPs |

---

## Integration with Security Platforms

### 1. SIEM (Splunk, ELK)

```
Splunk SPL:
index=* sourcetype IN (access_combined, iis, apache) 
| regex user_agent="(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)"
| stats count, values(url) as urls by clientip, user_agent
| where count > 50
| sort - count
```

```
ELK (Kibana Query Language):
http.request.user_agent: /(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)/i
AND @timestamp > now-30m
```

---

### 2. EDR (CrowdStrike, SentinelOne)

```
CrowdStrike Falcon (CQL):
event_simpleName=NetworkConnect 
| search UserAgent matches regex @"(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)"
| groupby [RemoteAddressIP4, UserAgent] stats count() as connections
| filter connections > 60
```

```
SentinelOne Singularity:
SELECT src_ip, user_agent, COUNT(*) as req_count
FROM network_events
WHERE user_agent REGEXP '(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)'
  AND timestamp > ago(20m)
GROUP BY src_ip, user_agent
HAVING req_count > 80
```

---

### 3. KQL Rule 

```
KQL
YourLogTable
| where isnotempty(UserAgent)
| where UserAgent matches regex @"(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)"
```

---

### 4. WAF / Firewall (Cloudflare, Nginx, Suricata)

```
Cloudflare Firewall Rule (Expression):
(http.user_agent matches "(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)")
```

```
Nginx:
set $block_llm 0;
if ($http_user_agent ~* "(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)") {
    set $block_llm 1;
}
if ($block_llm = 1) {
    return 403;
}
```

```
Suricata Rule:
alert http any any -> $HOME_NET any (
    msg:"LLM Crawler - Full Regex Match"; 
    flow:to_server; 
    http.user_agent; pcre:"/^(?i)(AI2Bot|Amazonbot|Andibot|Anthropic-Claude|Bard-Ai|Brightbot|Character-AI|ChatGPT-(Browser|User|User-v2)|ClaudeBot|claude-web|Cohere-(Ai|Command|ai)|Cotoyogi|Crawlspace|DeepseekBot|Devin|FirecrawlAgent|GPTBot|Gemini-(Ai|Deep-Research)|Google-(CloudVertexBot|Extended|NotebookLM)|Groq-Bot|HuggingFace-Bot|IbouBot|ImagesiftBot|Kangaroo Bot|MistralAI-User|OAI-SearchBot|PanguBot|Perplexity-(Stealth|User|Bot)|Replicate-Bot|RunPod-Bot|TerraCotta|TimpiBot|Together-Bot|Webzio-Extended|YouBot|anthropic-ai|bigsur\.ai|xAI-Bot)/"; 
    classtype:policy-violation; 
    sid:20251116; rev:1;
)
```

---
