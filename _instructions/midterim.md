## 1. What HAW-KI is currently using

Based on the current project configuration, HAW-KI runs:

* **Model:** `openai/gpt-oss-20b`
* **Serving name:** `hawki-local`
* **Inference engine:** vLLM
* **GPU:** RTX 5090 32 GB
* **Configured context:** 32,768 tokens
* **Configured concurrency:** up to four sequences
* **GPU-memory target:** approximately 88%

The important distinction is:

> **gpt-oss-20b is the LLM. vLLM is the inference server.**

vLLM loads the model, manages GPU memory and KV cache, batches requests, and exposes an OpenAI-compatible endpoint. It does not provide intelligence by itself.

### Model architecture

gpt-oss-20b is a mixture-of-experts model with approximately:

| Property                    |        gpt-oss-20b |
| --------------------------- | -----------------: |
| Total parameters            |                21B |
| Active parameters per token |               3.6B |
| Layers                      |                 24 |
| Experts                     | 32 total, 4 active |
| Native context              |               128K |
| Modalities                  |          Text only |
| License                     |         Apache 2.0 |

Because only part of the model activates for each token, it provides relatively fast inference while retaining more total parameter capacity than a similarly fast dense model. It supports adjustable reasoning effort, tool use, structured outputs, and agent-oriented workflows. OpenAI describes its training emphasis as primarily English, STEM, coding, and general knowledge. ([OpenAI][1])

Your 32K context limit is lower than the model’s native 128K limit, but it is sensible for a single 32 GB GPU. Increasing context consumes KV-cache memory, reducing concurrency and throughput.

### What it is good at

For HAW-KI, gpt-oss-20b is suitable for:

* Alert summarization
* Converting analyst language into structured requests
* Log-query planning
* Explaining Suricata rules
* Producing JSON actions
* Short investigation chains
* Code and configuration analysis
* Tool selection
* High-volume local triage

Its main weaknesses are:

* Less reliable deep reasoning than current frontier API models
* Limited broad-domain knowledge relative to larger models
* Primarily English-oriented training
* Text-only input
* Greater sensitivity to prompt formatting and chat-template mistakes
* More frequent errors on ambiguous, long-horizon investigations

OpenAI explicitly notes that gpt-oss-20b performs strongly on math, coding, and tool-use tasks but trails larger models on knowledge-heavy evaluations because of its smaller size. ([OpenAI Deployment Safety Hub][2])

Also, several Suricata problems we encountered were not purely model failures. They resulted from our backend classifiers, deterministic shortcuts, and response-routing logic. A larger model would reduce some ambiguity, but it would not replace properly designed validation and authorization layers.

---

## 2. Appropriate higher-reasoning local models

I would not immediately replace gpt-oss-20b with the largest available model. The useful question is:

> Which model provides a measurable reasoning improvement while remaining operationally reasonable on one RTX 5090?

### Primary recommendation: GLM-4.7-Flash

**GLM-4.7-Flash** is currently the strongest practical upgrade candidate for your workstation.

It is a 30B-total, approximately 3B-active MoE model intended for lightweight deployment. Its official model card reports stronger results than gpt-oss-20b on knowledge reasoning, software engineering, agent tasks, and browsing evaluations. For example, the published comparison reports GPQA 75.2 versus 71.5 and SWE-bench Verified 59.2 versus 34.0, although these are vendor-published results and should be verified on HAW-KI’s own evaluation set. ([Hugging Face][3])

**Why it fits HAW-KI:**

* Stronger multi-step reasoning
* Better agent and tool-use behavior
* Better software-engineering performance
* MoE efficiency
* Similar general deployment class to your current model
* Likely feasible at 4-bit quantization on 32 GB VRAM

A 30B model at four bits is roughly 15 GB in raw weight storage. Runtime overhead, quantization metadata, CUDA workspaces, and KV cache would raise actual use, but 32K-context single-user or low-concurrency deployment should be realistic. This needs direct benchmarking with the chosen vLLM quantization format.

**Recommended role:** complex investigations, incident reconstruction, resolution planning, and report generation.

---

### Reasoning and Korean-language alternative: Magistral Small 1.2

**Magistral Small 1.2** is a 24B reasoning model. Mistral states that it can run on a single RTX 4090 or a 32 GB system once quantized. It supports Korean, explicit reasoning traces, vision input, a 128K context window, and vLLM deployment. ([Hugging Face][4])

It is particularly attractive for HAW-KI when you need:

* Better Korean responses
* More disciplined explanatory reasoning
* Screenshot or image analysis
* Rule-review and configuration-review tasks
* A dedicated critic or reviewer model
* Better Markdown and answer formatting

It may not outperform GLM-4.7-Flash across every agentic benchmark, but it is a strong specialist for analysis and second-pass review.

**Recommended role:** investigation critic, rule reviewer, Korean analyst interface, and multimodal evidence interpretation.

---

### Balanced multilingual alternative: Qwen3-30B-A3B

**Qwen3-30B-A3B** has approximately 30.5B total parameters and 3.3B active parameters. It supports thinking and non-thinking modes, agent tool integration, more than 100 languages and dialects, and up to 128K context with extension. Qwen officially recommends vLLM and SGLang for deployment. ([Qwen][5])

Its main strengths for this project are:

* Strong multilingual operation
* Good Korean and Chinese handling
* Explicit thinking-mode control
* Mature local ecosystem
* Efficient MoE architecture
* Good instruction following
* Tool-call support

I would treat it as a **balanced alternative**, rather than assuming it is categorically stronger than gpt-oss-20b. Its advantage is broader multilingual and conversational behavior, not necessarily a decisive improvement on every reasoning task.

---

### Same-family high-end option: gpt-oss-120b

gpt-oss-120b is the cleanest architectural upgrade because it retains the same model family, reasoning controls, tool conventions, and Harmony-format behavior. OpenAI reports near-o4-mini performance on core reasoning benchmarks. However, the official deployment target is approximately **80 GB of GPU memory**, so it does not fit your current RTX 5090. ([OpenAI][1])

You could technically use aggressive quantization and CPU offloading, but throughput and latency would probably be inappropriate for an interactive SOAR.

It becomes reasonable with:

* One 80 GB accelerator
* Multiple GPUs using tensor parallelism
* A separate inference server
* A private cloud GPU node

I would not redesign the current workstation around this model yet.

---

## 3. Recommended model hierarchy

The strongest architecture is not “replace the 20B model with one larger model.” It is model routing.

| Workload                         | Recommended model                                   |
| -------------------------------- | --------------------------------------------------- |
| Alert normalization              | gpt-oss-20b                                         |
| Simple alert explanation         | gpt-oss-20b                                         |
| Query parameter extraction       | Deterministic code or gpt-oss-20b                   |
| Suricata syntax generation       | Deterministic compiler plus gpt-oss-20b             |
| Multi-source investigation       | GLM-4.7-Flash                                       |
| Incident timeline reconstruction | GLM-4.7-Flash                                       |
| Complex remediation planning     | GLM-4.7-Flash                                       |
| Korean-language review           | Magistral Small 1.2                                 |
| Screenshot or visual evidence    | Magistral Small 1.2                                 |
| Action validation                | Deterministic validators plus optional critic model |

This preserves low latency for ordinary work and spends more reasoning compute only where it adds value.

My specific recommendation is:

> **Keep gpt-oss-20b as HAW-KI’s fast operational model and add GLM-4.7-Flash as the deep-investigation model.**

Magistral Small can later be added as a review or multimodal specialist.

---

## 4. Are local models better than API models?

Not generally.

Current frontier APIs are materially stronger in broad reasoning, unfamiliar problems, long-horizon coding, multimodal analysis, and large-context synthesis. For example, OpenAI’s current GPT-5.5 API model supports reasoning levels through `xhigh`, a 1.05-million-token context, 128K output, and is positioned for complex professional and agentic work. ([OpenAI][6])

Therefore:

> **A local 20B or 30B model is unlikely to outperform a current frontier API model on raw general intelligence.**

Local models are better in a different dimension: **system control**.

### Where local deployment is better

#### Data confidentiality

Raw alerts, packet metadata, logs, host artifacts, usernames, internal IP addresses, process trees, and incident evidence can remain inside your network.

This is particularly important for:

* Classified or sensitive environments
* Personal information
* Incident-response evidence
* Malware samples
* Proprietary source code
* Internal network topology

OpenAI identifies control, data residency, and customization as core reasons to use open-weight models. ([OpenAI Help Center][7])

#### Full customization

You control:

* Model weights
* Quantization
* System prompt
* Chat template
* Reasoning budget
* Context handling
* Tool schema
* Fine-tuning
* LoRA adapters
* Output validators
* Safety policy
* Model version

An API model’s internal weights and training cannot be modified.

#### Stable and reproducible behavior

You can pin one exact:

* Model checkpoint
* Tokenizer
* Quantization
* vLLM release
* Prompt
* Sampling configuration

This is valuable for forensic and compliance workflows because the same input can be evaluated against a known model version.

#### Local tool access

The model can communicate directly with:

* Elasticsearch
* Wazuh
* Suricata
* Velociraptor
* Host inventory
* Internal threat intelligence
* Private runbooks
* Asset databases

The system does not need to serialize and transmit large volumes of telemetry to an external service.

#### High-volume marginal cost

After purchasing the hardware, high-volume inference does not incur a provider token charge. You instead pay for:

* Electricity
* Hardware depreciation
* Maintenance
* Engineering
* Storage
* Cooling

For repeated triage of thousands of alerts, this can be economically attractive.

#### Offline availability

The system can continue to:

* Interpret alerts
* Search local logs
* Generate reports
* Review rules
* Produce response proposals

even during internet or provider outages.

---

## 5. What gpt-oss-20b can do better than an API model

Again, not general reasoning. It can be better at **your specific operational environment**.

### Organization-specific knowledge

With local retrieval, gpt-oss-20b can know:

* Which host belongs to which user
* Which services normally run on each server
* Which interfaces are external
* Which subnets are trusted
* Which Suricata rules are active
* Which incidents occurred previously
* Which exceptions your organization permits
* Which runbook applies to a given alert

An API model without this context may be more intelligent but less operationally informed.

### Exact structured integration

Your local model can be optimized specifically for schemas such as:

```text
evidence[]
queries[]
actions[]
risk
requires_approval
payload
```

It can become more consistent at producing HAW-KI’s exact data structures than a general API model that has not been tuned or evaluated against them.

### Repetitive SOC workloads

For narrow tasks such as:

* Extract IP addresses and hashes
* Map alerts to MITRE techniques
* Summarize 50 Elasticsearch events
* Normalize Suricata rule requests
* Identify missing action parameters
* Format incident timelines

a specialized local model can match or exceed a larger API model while being faster, private, and cheaper.

### Stable domain behavior

An API provider may update model aliases, safety behavior, tool conventions, or output tendencies. Your local checkpoint stays fixed until you deliberately change it.

### Direct handling of sensitive volume

A frontier API may reason better over one incident, but locally you can process much larger quantities of sensitive logs without external data transfer or token-budget concerns.

---

## 6. How HAW-KI can become better than API-based SOAR systems

The objective should not be:

> Make a local model universally smarter than GPT-5.5.

That is unrealistic for this workstation.

The achievable objective is:

> Make HAW-KI more accurate, safer, faster, and more useful than a generic API model on our exact security environment.

### Build a HAW-KI evaluation suite

Before switching models, construct a fixed test set containing:

* Suricata alerts
* Wazuh alerts
* Elasticsearch investigations
* Benign and malicious process trees
* Suspicious files
* False-positive scenarios
* Rule-generation requests
* Velociraptor response proposals
* Korean and English analyst prompts

Measure:

* Evidence precision
* Evidence recall
* Query correctness
* Hallucination rate
* Action safety
* Rule syntax validity
* False-positive reasoning
* Tool-call success
* Korean answer quality
* Latency
* Tokens per investigation

Without this, model comparisons are mostly subjective.

### Use typed tools instead of free-form reasoning

The model should not fabricate Elasticsearch queries or Velociraptor commands as unvalidated text.

Use typed functions such as:

```text
search_alerts(host, severity, start, end)
search_processes(host, process_name, hash)
retrieve_file(host, path)
isolate_host(host, reason)
validate_suricata_rule(rule)
stage_suricata_rule(rule_id, host, interface)
```

This is where a local 20B model can beat a more intelligent API model: the available action space is constrained and validated.

### Build security-specific retrieval

The model should retrieve:

* Asset inventory
* Network topology
* Historical incidents
* Existing Suricata rules
* Approved response procedures
* Known exceptions
* Threat-intelligence records
* Baseline process and network behavior
* MITRE ATT&CK mappings
* Internal ownership information

The answer should cite retrieved evidence, rather than relying on model memory.

### Fine-tune narrow behaviors

Do not initially fine-tune the model to “know cybersecurity.”

Fine-tune it for specific HAW-KI behaviors:

* Correct structured JSON
* Evidence-versus-inference distinction
* Missing-field questions
* Risk classification
* Rule explanations
* Query planning
* Korean analyst terminology
* Refusing unsupported conclusions
* Producing approval-ready actions

A relatively small LoRA adapter can materially improve consistency in these narrow areas.

### Learn from analyst decisions

Use approval history as feedback:

* Which proposed actions were approved?
* Which were rejected?
* Which fields were edited?
* Which generated rules produced false positives?
* Which queries returned useful evidence?
* Which conclusions were corrected?

This creates organization-specific preference data that no external API model possesses.

### Add a critic stage

For high-risk actions:

1. Primary model proposes an investigation or action.
2. A second reasoning pass critiques it.
3. Deterministic validators inspect syntax and policy.
4. The analyst approves or rejects it.

The critic can check:

* Unsupported assumptions
* Missing evidence
* Excessive operational impact
* Wrong host or interface
* Rule breadth
* Rollback feasibility
* False-positive risk

### Separate evidence from interpretation

Every response should distinguish:

* **Observed:** returned directly by tools
* **Derived:** calculated from observed data
* **Inferred:** model interpretation
* **Proposed:** not yet executed
* **Approved:** authorized
* **Executed:** confirmed by the gateway

This will improve trustworthiness more than simply installing a larger model.

### Use hybrid local/API escalation

For highly ambiguous or severe incidents, HAW-KI could optionally send a redacted case summary—not raw logs—to a frontier API model.

A strong architecture would be:

```text
Local tools and evidence collection
            ↓
gpt-oss-20b normalization
            ↓
GLM-4.7-Flash local investigation
            ↓
Deterministic validation
            ↓
Optional redacted frontier-API review
            ↓
Human approval
```

This preserves sensitive evidence locally while obtaining frontier reasoning only when justified.

---

## 7. Practical conclusion

Your current gpt-oss-20b model is a good **operational foundation**, but it should not be the sole reasoning engine for every HAW-KI function.

The most practical progression is:

1. **Retain gpt-oss-20b** for routine triage, extraction, summarization, and structured tool routing.
2. **Add GLM-4.7-Flash** as the higher-reasoning local model for deep investigations and incident planning.
3. **Consider Magistral Small 1.2** for Korean-language analysis, visual evidence, and second-pass review.
4. Develop a **HAW-KI-specific evaluation suite** before choosing a permanent replacement.
5. Improve retrieval, typed tools, validation, and analyst feedback before attempting model fine-tuning.
6. Treat gpt-oss-120b or models such as Mistral Small 4 as future server-class options, not immediate RTX 5090 deployments.

The defensible project claim is not that a local model is universally superior to API models. It is:

> **HAW-KI can outperform general API-based assistants on private, organization-specific incident response by combining local models with proprietary telemetry, deterministic security tools, domain retrieval, validated actions, and analyst feedback.**

[1]: https://openai.com/index/introducing-gpt-oss/?utm_source=chatgpt.com "Introducing gpt-oss | OpenAI"
[2]: https://deploymentsafety.openai.com/gpt-oss/openai-prs?utm_source=chatgpt.com "gpt-oss-120b & gpt-oss-20b Model Card - OpenAI Deployment Safety Hub"
[3]: https://huggingface.co/zai-org/GLM-4.7-Flash?utm_source=chatgpt.com "zai-org/GLM-4.7-Flash · Hugging Face"
[4]: https://huggingface.co/mistralai/Magistral-Small-2509 "mistralai/Magistral-Small-2509 · Hugging Face"
[5]: https://qwenlm.github.io/blog/qwen3/?utm_source=chatgpt.com "Qwen3: Think Deeper, Act Faster | Qwen"
[6]: https://openai.com/index/introducing-gpt-5-5/?utm_source=chatgpt.com "Introducing GPT-5.5 | OpenAI"
[7]: https://help.openai.com/en/articles/11870455?utm_source=chatgpt.com "OpenAI open-weight models (gpt-oss) | OpenAI Help Center"
