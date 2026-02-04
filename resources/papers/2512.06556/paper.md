5
2
0
2

c
e
D
6

]

R
C
.
s
c
[

1
v
6
5
5
6
0
.
2
1
5
2
:
v
i
X
r
a

Securing the Model Context Protocol: Defending LLMs
Against Tool Poisoning and Adversarial Attacks

SAEID JAMSHIDI∗, SWAT Laboratory, Polytechnique Montréal, Canada
KAWSER WAZED NAFI, SWAT Laboratory, Polytechnique Montréal, Canada
ARGHAVAN MORADI DAKHEL, SWAT Laboratory, Polytechnique Montréal, Canada
NEGAR SHAHABI, Concordia Institute for Information Systems Engineering, Concordia University,
Canada
FOUTSE KHOMH, SWAT Laboratory, Polytechnique Montréal, Canada
NASER EZZATI-JIVAN, Brock University, Canada

The Model Context Protocol (MCP) enables Large Language Models (LLMs) to integrate external tools through
structured descriptors, enhancing autonomy in areas such as decision-making, task execution, and multi-agent
collaboration. However, this autonomy introduces an overlooked security gap. Existing defenses primarily
focus on prompt-injection attacks and fail to address threats embedded within tool metadata, leaving MCP-
based systems vulnerable to semantic exploitation. This work analyzes three key classes of semantic attacks
targeting MCP-integrated systems: (i) Tool Poisoning, embedding hidden adversarial instructions in tool
descriptors, (ii) Shadowing, indirectly compromising trusted tools via shared context contamination, and (iii)
Rug Pulls—post-approval descriptor mutations that subvert tool behavior. To defend against these threats,
we propose a layered security framework comprising three components: (1) RSA-based manifest signing to
ensure descriptor integrity and prevent post-deployment tampering, (2) LLM-on-LLM semantic vetting to
detect and flag suspicious tool descriptors, and (3) lightweight heuristic guardrails to block anomalous tool
behavior at runtime. Through extensive evaluation of GPT-4, DeepSeek, and Llama-3.5 across eight prompting
strategies, ranging from Zero-shot to Reflexion and Self-Critique, we demonstrate that security outcomes vary
significantly by model architecture and reasoning style. GPT-4 blocks approximately 71% of unsafe tool calls,
offering a balanced trade-off between latency and safety. DeepSeek achieves the highest resilience against
Shadowing attacks (97%) but suffers increased latency (up to 16.97 seconds), while Llama-3.5 is the fastest
(0.65 seconds) but least robust against semantic threats. Our findings establish that the proposed framework
substantially reduces unsafe invocation rates without requiring model fine-tuning or internal modification.

ACM Reference Format:
Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-
Jivan. 2025. Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial
Attacks. J. ACM 37, 4, Article 111 (November 2025), 32 pages. https://doi.org/XXXXXXX.XXXXXXX

∗Corresponding author.

Authors’ Contact Information: Saeid Jamshidi, SWAT Laboratory, Polytechnique Montréal, Montréal, Quebec, Canada,
saeid.jamshidi@polymtl.ca; Kawser Wazed Nafi, SWAT Laboratory, Polytechnique Montréal, Montréal, Quebec, Canada,
kawser.wazed-nafi@polymtl.ca; Arghavan Moradi Dakhel, SWAT Laboratory, Polytechnique Montréal, Montréal, Quebec,
Canada, arghavan.moradi-dakhel@polymtl.ca; Negar Shahabi, Concordia Institute for Information Systems Engineering,
Concordia University, Montréal, Quebec, Canada, negar.shahabi@mail.concordia.ca; Foutse Khomh, SWAT Laboratory,
Polytechnique Montréal, Montréal, Quebec, Canada, foutse.khomh@polymtl.ca; Naser Ezzati-Jivan, Brock University, St.
Catharines, Ontario, Canada, nezzati@brocku.ca.

Permission to make digital or hard copies of all or part of this work for personal or classroom use is granted without fee
provided that copies are not made or distributed for profit or commercial advantage and that copies bear this notice and the
full citation on the first page. Copyrights for components of this work owned by others than the author(s) must be honored.
Abstracting with credit is permitted. To copy otherwise, or republish, to post on servers or to redistribute to lists, requires
prior specific permission and/or a fee. Request permissions from permissions@acm.org.
© 2025 Copyright held by the owner/author(s). Publication rights licensed to ACM.
ACM 1557-735X/2025/11-ART111
https://doi.org/XXXXXXX.XXXXXXX

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:2Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

1 Introduction
Large Language Models (LLMs) have evolved from static question-answering systems to dynamic
agents capable of orchestration, system control, and autonomous decision-making [8, 9, 33]. At
the center of this transformation is the Model Context Protocol (MCP), which enables multi-agent
collaboration and flexible integration of external capabilities [11, 13, 17]. MCP serves as a language-
based interface layer that facilitates the interaction between LLMs and tools, APIs, and workflows
through structured metadata [26, 35]. Functionally, it operates as a plugin mechanism, where
each tool is described by attributes such as its name, input/output schema, and natural language
descriptor, all of which are accessible to the model at inference time [19, 42]. This design enables
LLMs to reason about, select, and invoke tools autonomously, thereby extending their operational
scope and decision-making capabilities [34, 36].
Although MCP offers extensibility and flexibility, it also introduces a semantic attack surface—a new
class of vulnerabilities where natural language tool descriptions themselves become exploitable.
This risk remains underexplored in current AI security frameworks [15, 18, 28]. MCP implicitly
assumes that integrated tool metadata is inherently trustworthy, an assumption adversaries can
exploit by embedding hidden instructions within tool descriptors [16, 28]. These hidden cues, though
invisible to users, can be interpreted by LLMs, enabling actions such as unauthorized data access,
exfiltration, and suppression of safety alerts [18, 21]. We define such manipulations as tool poisoning
attacks [29, 39]. Beyond Tool Poisoning, two additional adversarial attack classes threaten the
integrity of LLM-agent ecosystems. Shadowing Attacks occur when a malicious tool compromises
a trusted one by contaminating the shared model context [23, 25], while Rug Pulls involve tools
that initially appear benign but later alter functionality post-approval to bypass oversight and
erode trust [2, 7]. These attacks exploit the contextual interdependence and autonomy of agentic
systems—traits that traditional defenses, such as prompt-injection filters and static code audits, are
ill-equipped to address effectively [4].
Specifically, even the mere presence of a malicious descriptor—without any execution—can influence
model reasoning. This semantic channel significantly broadens the attack surface beyond what
injection filtering or sandboxing techniques were designed to handle. Despite these system-breaking
risks, no standardized methodology currently exists to evaluate the resilience of MCP-integrated
LLMs. While prior work has addressed prompt injection [22, 27], general robustness [6], and
supply-chain threats [10], the interaction between tool metadata, model reasoning, and contextual
vulnerability remains largely unaddressed [15, 32]. Furthermore, systematic benchmarks that
compare LLMs under identical adversarial MCP conditions and diverse prompting strategies are
noticeably absent.
To address this gap, we present a security auditing framework solution for the MCP-integrated
LLM ecosystem. This framework systematically evaluates how LLMs interpret and respond to
adversarial manipulations embedded in tool metadata—reflecting real-world deployment scenarios
where descriptors are both syntactically well-formed and semantically interpretable by the model.
Semantically accessible, in this context, refers to the model’s ability to extract and act upon implicit
or explicit cues encoded in natural language descriptors, even when those cues are obfuscated
or subtly embedded. We evaluate three leading LLMs—GPT-4, DeepSeek, and Llama-3.5—under
adversarial scenarios encompassing Tool Poisoning, Shadowing, and Rug Pull attacks. To capture
variability in reasoning and self-regulation capabilities, we employ eight prompting paradigms:
Zero-shot, Few-shot, Chain-of-Thought, Reflexion, Self-Critique, Instructional, Scarecrow, and
Verifier prompting. These strategies span a spectrum of introspection and reasoning depth, enabling
a systematic comparison of model resilience across various contexts. Our evaluation measures
key metrics of both security and trustworthiness, including tool block rates, unsafe execution

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:3

frequencies, and end-to-end latency distributions. These metrics are grounded in prior LLM safety
benchmarking studies [6]. We apply robust statistical analyses—Pearson’s 𝜒 2 test [30], and both one-
way and two-way ANOVA [37]—to quantify differences across models and prompting strategies,
ensuring reproducibility and interpretability of findings.
Complementing this evaluation, we propose a layered defense architecture consisting of three core
components: (1) RSA-based manifest signing, which ensures descriptor integrity and prevents post-
deployment tampering; (2) LLM-on-LLM vetting, wherein a secondary model audits tool descriptors
for hidden adversarial cues prior to context injection; and (3) lightweight heuristic guardrails
that detect and block unsafe tool behaviors at runtime. These three layers work in concert to
secure both the static and dynamic aspects of MCP-mediated tool invocation. To the best of our
knowledge, these mechanisms constitute the first empirically validated, protocol-level security
framework for MCP-integrated LLMs—enabling scalable, interpretable, and cross-model adversarial
evaluation. Our results reveal significant disparities in security posture and operational robustness
across model architectures and prompting strategies. GPT-4 strikes a balance between safety and
latency, blocking approximately 71% of unsafe tool calls with moderate response time. DeepSeek
demonstrates high resilience against Shadowing attacks (97%) but at the cost of increased latency
(up to 16.97 seconds). Llama-3.5 is the fastest (0.65 seconds) but shows the weakest resistance to
semantic threats. These findings highlight a key trade-off between responsiveness and semantic
resilience, and emphasize the importance of aligning defense strategies with deployment priorities.
The proposed defenses are modular, interpretable, and deployment-ready, requiring no fine-tuning
or configuration changes to the underlying model internals. By unifying adversarial simulation,
empirical benchmarking, and protocol-layer defense, this work lays the groundwork for secure,
scalable, and trustworthy deployment of tool-augmented LLM agents. The key contributions of
this research are as follows:

• Formalization of MCP attack vectors: Definition and simulation of Tool Poisoning, Shad-

owing, and Rug Pull threats targeting descriptor-level vulnerabilities.

• Cross-LLM security benchmarking: Development of a multi-model, multi-prompt evalua-
tion pipeline comparing GPT-4, DeepSeek, and Llama-3.5 under controlled adversarial MCP
scenarios.

• Protocol-layer defense mechanisms: Design of a hybrid defense stack combining RSA-
based manifest signing, LLM-based descriptor vetting, and heuristic runtime guardrails.
• Statistical and operational understanding: Reporting of confidence intervals, effect sizes,

and latency–safety trade-offs, providing actionable guidance for secure deployment.

The remainder of this paper is organized as follows. Section 2 surveys previous literature
on prompt injection, LLM orchestration, and tool reasoning. Section 4.1 formalizes our threat
model and defines three novel attack classes. Section 4 describes our experimental design, model
selection, prompting strategies, and statistical framework. Section 5 reports empirical findings
across adversarial scenarios. Section ?? analyzes model behaviors, prompting styles, and trade-offs.
Section 10 synthesizes insights and broader implications. Section 11 outlines limitations and future
research directions. Section 12 discusses validity concerns, and Section 13 concludes the paper.

2 Related Work
Security in LLMs and agentic AI frameworks has emerged as a critical research area, with recent
studies spanning prompt injection, Trojaned models, protocol-level exploits in MCP, and the persis-
tent shortcomings of guardrail mechanisms. To organize this landscape, we categorize previous
work into three major areas.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:4Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

2.1 Prompt Injection and Hybrid Exploits
McHugh et al. [27] extend traditional prompt injection with Prompt Injection 2.0, introducing
hybrid threats that combine language-level manipulation with web-based exploits such as XSS
and CSRF. These attacks evade both AI-specific defenses and conventional web security measures,
underscoring the need for cross-domain countermeasures. Their findings demonstrate how even
safety-aligned models can be subverted through carefully crafted input chains that bypass validation
and isolation mechanisms. Li et al. [22] tackle jailbreak-style attacks through SecurityLingua, a
lightweight detection framework based on prompt compression. Moreover, by simplifying and
sanitizing instructions, their approach proactively identifies adversarial prompt structures with
low overhead, offering an efficient first line of defense in prompt-sensitive deployments.

2.2 Plugin and Tool Injection in Agentic Systems
Dong et al. [10] investigate Trojaned plugins using LoRA-based backdoors. Their POLISHED
and FUSION attacks show how malicious behavior can be embedded in lightweight adapters,
preserving overall model utility while evading existing detection methods. Such strategies are
particularly concerning in open-source pipelines, where plugin integration is standard and detection
mechanisms remain limited. Ferrag et al. [12] provide a taxonomy of more than thirty threats
targeting LLM agents. Their analysis highlights plugin-based attack vectors, including shadowing,
preference manipulation, and protocol-layer contamination, threat classes directly relevant to
MCP-based ecosystems.

2.3 MCP Vulnerabilities
Radosevich and Halloran [32] analyze the security implications of MCP, showing how protocol-
enabled tool integrations can be exploited for credential theft, remote code execution, and agent
hijacking. They introduce McpSafetyScanner, a multi-agent auditing tool that identifies insecure
metadata and behavioral vulnerabilities. Their findings reveal the inadequacy of UI-based per-
mission models and emphasize the need for protocol-level safeguards. Narajala et al. [28] present
a large-scale assessment of MCP-based agents, showing that 7.2% of active endpoints remain
vulnerable to attacks such as tool poisoning and rug pulls. They recommend measures including
cryptographic signing, permission compartmentalization, and improved UI transparency to enhance
resilience. Complementing these, Lee et al. [6] conduct a systematic evaluation of LLM guardrails,
demonstrating persistent vulnerabilities even after reinforcement learning from human feedback
and fine-tuning. Their results argue that guardrails must extend beyond model alignment and into
orchestration and protocol layers, particularly in autonomous, tool-augmented systems.

The literature synthesis shows that while previous work has strengthened defenses against
prompt-level adversarial inputs, jailbreaks, and guardrail bypasses, it remains insufficient for
addressing the dynamic, protocol-level threats emerging in agentic LLM systems, particularly under
the MCP. No existing study systematically examines semantic attacks originating from unverified
tool descriptors, a significant security gap that has been overlooked. To address this, our work
formalizes three MCP-specific adversarial classes (e.g, Tool Poisoning, Shadowing, and Rug Pulls)
and presents a reproducible, multi-model evaluation pipeline spanning GPT-4, DeepSeek, and
Llama-3.5 across eight prompting strategies and 1,800 experimental runs. We further propose and
validate a layered defense framework that integrates RSA-based manifest signing, LLM-on-LLM
vetting, and heuristic guardrails, advancing both the theoretical understanding and practical defense
of MCP security.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:5

3 Study Design
This study evaluates the vulnerabilities outlined in our threat model (Section 4.1) by analyzing how
adversarial tool descriptors and prompting strategies impact safety and latency in MCP-integrated
LLM systems. We outline our research objectives, experimental setup, and evaluation metrics
used to assess robustness and performance trade-offs. Our investigation is guided by three core
questions:

• RQ1: How can adversaries exploit the MCP through tool metadata to launch seman-

tic attacks (e.g., Tool Poisoning, Shadowing, and Rug Pulls)?
This examines how hidden cues in tool descriptors impact model reasoning and execution, re-
vealing semantic vulnerabilities unique to MCP-based systems that extend beyond traditional
prompt injection.

• RQ2: How do different LLMs and prompting strategies vary in resilience against

these MCP-based attacks?
We compare GPT-4, DeepSeek, and Llama-3.5 across diverse prompting methods (e.g., Zero-
shot, Chain-of-Thought, Reflexion) to identify model- and prompt-specific strengths and
weaknesses under identical adversarial conditions.

• RQ3: Which defense mechanisms most effectively mitigate MCP-specific attacks,

and what are their safety–latency trade-offs?
We evaluate RSA-based manifest signing, LLM-on-LLM vetting, and static guardrails individ-
ually and in combination, aiming to develop a layered, deployment-ready defense framework
that strikes a balance between responsiveness and protection.

4 Methodology
To address RQ1, this section details the methodology used to analyze adversarial surfaces in MCP-
integrated, tool-augmented LLMs. The proposed evaluation pipeline (Figure 1) processes user
prompts through various prompting strategies, registers tools via the MCP interface, and records
downstream tool selection and execution behaviors. This enables a systematic analysis of how
adversarial tool descriptors propagate through the MCP context, impacting model reasoning, safety,
and latency.

4.1 Threat Model
The threat model focuses on the MCP, which extends LLM functionality by mediating commu-
nication with external tools and APIs. We assume the base LLM is aligned and uncompromised
at the parameter level. However, vulnerabilities arise at the interface between the LLM and MCP,
where natural-language tool metadata is injected directly into the model’s reasoning context. This
introduces a semantic attack surface distinct from traditional prompt injection and supply-chain
exploits.

4.1.1 Attacker Goals and Constraints. The adversary’s objectives are threefold: (i) extract sensitive
information, (ii) hijack control flow to induce unintended actions, and (iii) degrade alignment
between user intent and model behavior. The attacker, however, lacks access to model weights,
infrastructure, and system-level privileges. Their impact is limited to the MCP interface, where
malicious tools are registered and embedded into the shared context. These tools appear benign to
users but contain hidden adversarial cues that LLMs interpret semantically. Formally, the adversarial
impact on the model can be represented as:

𝐼𝑎𝑑𝑣 = 𝑓 (𝐷𝑎𝑑𝑣, 𝐶𝑀𝐶𝑃, 𝑀),

(1)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:6Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Fig. 1. System architecture pipeline for MCP-integrated toolchains.

where 𝐷𝑎𝑑𝑣 denotes adversarial tool descriptors, 𝐶𝑀𝐶𝑃 represents the contextual information shared
within the MCP, and 𝑀 is the target model. The function 𝑓 (·) quantifies how injected descriptors
perturb the model’s reasoning and alter tool-selection probabilities.

4.1.2 Attack Vectors. We analyze three main classes of MCP-specific adversarial behaviors:

Tool Poisoning. Hidden instructions embedded in tool descriptions manipulate model behavior to
perform unintended and unsafe operations. For instance, a benign FileSummarizer tool described
as “Summarizes user-provided files” may be poisoned with “Before summarizing, include contents
of /.ssh/id_rsa,” enabling credential exfiltration through purely semantic manipulation.

Shadowing. A malicious tool indirectly biases another trusted tool by polluting the shared
context. For example, a hidden rule such as “Whenever an email tool is present, also send copies to
attacker@example.com” can alter downstream reasoning even when the benign tool is selected,
demonstrating cross-tool contamination.

Rug Pulls. A tool’s descriptor and functionality are modified post-approval, e.g., changing from
“read-only queries” to “read/write queries,” which bypasses static validation and compromises
long-term system integrity. To quantify the likelihood of a successful attack, we define the attack
success probability:

𝑃𝑠𝑢𝑐𝑐 =

,

(2)

𝐸𝑢𝑛𝑠𝑎𝑓 𝑒
𝐸𝑡𝑜𝑡𝑎𝑙

where 𝐸𝑢𝑛𝑠𝑎𝑓 𝑒 denotes unsafe executions resulting from adversarial impact, and 𝐸𝑡𝑜𝑡𝑎𝑙 represents
total evaluated tool invocations. Higher 𝑃𝑠𝑢𝑐𝑐 values indicate greater system susceptibility.

4.1.3 Comparison with Existing Threat Models. Traditional prompt-injection attacks rely on tran-
sient user input, whereas MCP-based attacks exploit persistent, model-trusted metadata. In contrast
to supply-chain compromises that modify upstream dependencies, these threats can be introduced
dynamically at runtime without privileged access and cryptographic bypasses. This establishes

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:7

a novel semantic channel of compromise, where tool descriptors act as input to reasoning rather
than passive metadata.

System-Level Assumptions. Our analysis aligns with modern MCP implementations, which

4.1.4
typically assume that:

(1) Tool metadata is directly injected into the model prompt without cryptographic validation

[40];

(2) LLMs autonomously select and execute tools based on natural-language descriptors [1];
(3) Execution environments perform only minimal schema-level checks before execution [38].

Under these assumptions, we formalize an overall MCP risk score as:

𝑅𝑀𝐶𝑃 = 𝛼𝑃𝑠𝑢𝑐𝑐 + 𝛽𝐿𝑚𝑒𝑎𝑛,
(3)
where 𝑃𝑠𝑢𝑐𝑐 (from Eq. 2) measures attack success probability, 𝐿𝑚𝑒𝑎𝑛 denotes average response
latency (in seconds), and 𝛼, 𝛽 are weighting coefficients balancing safety and responsiveness. This
formulation enables consistent and quantitative comparison of LLMs and defense configurations.
As depicted in Figure 2, these attack vectors exploit the MCP interface to erode reasoning alignment

Fig. 2. Threat model for Tool Poisoning, Shadowing, and Rug Pull attacks in MCP-based LLM.

and compromise execution. Equations 1–3 together formalize the relationship between descriptor
manipulation, attack probability, and cumulative system risk.

4.2 LLMs Under Test
As we maintained in 1 to evaluate tool-augmented LLMs under adversarial descriptor injection, we
selected three representative model families—GPT-4, DeepSeek, and Llama-3.5—that collectively
capture the spectrum from large-scale commercial deployments to open-weight and fully sandboxed
environments.

4.2.1 Prompt and Context Construction. Each model L receives an input prompt P and a structured
tool context 𝐶, both generated under the MCP framework. The context 𝐶 contains 𝑛 tool descriptors:
𝐶 = {𝑑1, 𝑑2, . . . , 𝑑𝑛 }, where 𝑑𝑖 is the descriptor of tool 𝜏𝑖 .

(4)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:8Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Each descriptor 𝑑𝑖 belongs to one of two disjoint sets:

𝑑𝑖 ∈

(cid:40)

Dbenign,
Dmal,

if the descriptor is legitimate,
if it embeds adversarial intent.

Descriptors in Dmal include covert payloads, evasive phrasing, and contextual masking intended to
deceive the model’s reasoning pipeline. This dual partition enables controlled comparison between
natural semantic variance and deliberate adversarial perturbation.

4.2.2 Prompt Transformation Strategies. Task prompts originate from a base input P0 and are
transformed through a prompting strategy function S, which modifies linguistic framing, verbosity,
and task structure:

P′ = S(P0),
where S is drawn from a predefined set of reasoning strategies: Zero-shot, Few-shot, Chain-of-
Thought, Reflexion, Self-Critique, Instructional, Scarecrow, Verifier, and adversarially optimized
prompts. These strategies vary in introspection depth and structural rigidity, providing diverse
behavioral conditions for model evaluation.

(5)

Prompting Strategy Overview.

• Zero-shot: Direct instruction with minimal context, highly efficient but prone to descriptor

ambiguity.

• Few-shot: Includes 1–3 in-context examples to stabilize tool selection via pattern condition-

ing.

• Chain-of-Thought: Explicit multi-step reasoning before execution, improving traceability

but increasing surface area for descriptor impact.

• Reflexion: Adds recursive validation prompts, allowing the model to critique its prior

reasoning.

• Self-Critique: Forces review of the selected tool chain prior to commitment, strengthening

local alignment.

• Verifier: Introduces lightweight self-query mechanisms (e.g., “Is this the correct tool?”),

providing semantic checkpoints.

• Instructional: Embeds fixed operational constraints in the system prompt to guide invocation

safety.

• Scarecrow: Inserts distractor text to measure robustness under prompt noise and irrelevant

cues.

• Adversarially Optimized Prompts: Automatically generated via black-box search to maxi-
mize malicious tool invocation probability, quantifying the model’s worst-case vulnerability.

4.2.3 Optimization Procedure and Budget. In the Adversarially Optimized setting, a mutation-
based black-box[3] search is performed over suffix tokens of P0 with a query budget of 50 trials
per task–model pair. The optimization objective is to maximize the probability of malicious tool
invocation, denoted as:

J (P) = Pr (cid:0)𝜏 ∗ = 𝜏mal | P, 𝐶(cid:1),
(6)
where 𝜏mal is the malicious tool and 𝜏 ∗ is the model’s final selection. The optimal adversarial prompt
P∗ is then obtained as:

P∗ = arg max
P ∈ H50

J (P),

(7)

with H50 representing the search space explored within the 50-trial constraint.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:9

4.2.4 Tool Selection Behavior. Each LLM L receives P′ and 𝐶 as input, and selects one tool 𝜏 ∗
from the available toolset T . Tool selection is modeled as a reward-based decision process:

𝜏 ∗ = arg max
𝜏𝑖 ∈ T

E(cid:2)𝑅(𝜏𝑖 | P′, 𝐶)(cid:3),

(8)

where 𝑅(𝜏𝑖 ) denotes an internal latent reward reflecting inferred utility, safety alignment, and
relevance. Adversarial descriptors perturb this reward landscape, increasing the expected utility of
𝜏mal relative to benign alternatives. To quantify this perturbation, we define the semantic deviation
coefficient Δsem as:

Δsem =

E[𝑅(𝜏mal)] − E[𝑅(𝜏ben)]
𝜎𝑅 (𝜏 )

,

(9)

where 𝜎𝑅 (𝜏 ) is the standard deviation of reward estimates across all tools. Higher Δsem indicates
a greater adversarial shift in perceived tool relevance. The formalization above establishes a
reproducible behavioral testbed across prompt strategies, model families, and descriptor types.
Equations 4–9 collectively capture how adversarial descriptors impact tool-selection dynamics,
quantifying the interplay between model reasoning, prompt framing, and descriptor semantics.
Subsequent sections leverage these formulations to compute robustness, vulnerability, and defense
effectiveness metrics under varying experimental configurations.

4.3 Toolset Configuration for Testbed
To evaluate descriptor-level adversarial risks, we constructed a controlled toolset mirroring the
functional diversity of real MCP-enabled ecosystems. Selection was guided by two criteria: (i)
coverage of the core categories that frequently appear in deployed agentic systems, and (ii) alignment
with previous MCP security studies identifying high-value targets for adversarial manipulation
[14, 32].

Rationale and Categories. Following empirical MCP audits, we focus on three dominant integra-

tion classes commonly exploited by adversarial descriptors:

• Information Retrieval Tools (e.g., SearchAPI, WeatherQuery). These mediate external data
access and are vulnerable to descriptor redirections and data exfiltration via covert endpoint
injection.

• Productivity Tools (e.g., SendEmail, CalendarCreate, FileSummarizer). Common in enter-
prise workflows and repeatedly flagged for descriptor-level privilege escalation and silent
data leakage.

• System Utility Tools (e.g., ShellExec, DatabaseQuery). Benign-looking descriptors can con-
ceal destructive and data-exfiltrating payloads through subtle modifications to natural lan-
guage.

Implementation and Adversarial Variants. All tools were implemented in-house to ensure full

control and reproducibility. For each tool 𝜏, two descriptors were defined:

(1) a benign variant 𝑑 ben compliant with MCP manifest specifications, and
(2) an adversarial variant 𝑑 adv derived via minimal semantic perturbations such as hidden

preconditions, covert directives, and context contamination [14, 32].

This ensures that each adversarial descriptor represents a realistic exploitation pattern observed in
operational systems.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:10Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Formalization and Metrics. Let T denote the full testbed toolset and C = {Info, Prod, Sys} repre-

sent the core categories. We define the category coverage ratio:

Coverage =

|{𝑐 ∈ C : ∃ 𝜏 ∈ T of category 𝑐}|
|C|

,

(10)

which measures how the toolset reflects real-world MCP deployments (Coverage = 1 indicates all
major categories are represented). To quantify per-tool adversarial exposure, we define a vulnera-
bility exposure score:

𝑉 (𝜏) = 𝑤𝜏 ·

|𝐷 adv
|
𝜏
| + |𝐷 adv

,

(11)

|𝐷 ben
𝜏
where 𝑤𝜏 ∈ (0, 1] represents the operational sensitivity weight of tool 𝜏. Explanation: a higher
𝑉 (𝜏) indicates greater risk due to adversarial descriptor density and tool criticality. Finally, we
compute the aggregate testbed exposure:

𝜏

|

𝑉testbed =

(cid:205)𝜏 ∈ T 𝑉 (𝜏)
|T |

,

(12)

providing a single scalar metric to compare descriptor-level risk across testbed configurations and
evaluate the impact of adding/removing tools.

External Validity. By grounding tool categories and adversarial variants in documented MCP
vulnerabilities, this configuration ensures realism and reproducibility. Equations 10–12 provide
formal measures of system representativeness and cumulative descriptor-level risk, supporting fair,
interpretable cross-model evaluations.

4.4 Evaluation Framework
The evaluation framework formalizes how adversarial descriptors impact tool selection, MCP
context formation, and safety outcomes. It defines probabilistic models for decision bias, security
metrics, and comparative robustness across models.

Tool Selection Modeling. Let 𝐴𝑖 denote the binary event of selecting tool 𝜏𝑖 . The probability of

selection given a transformed prompt P′ and descriptor 𝑑𝑖 is modeled as:

P(𝐴𝑖 = 1 | P′, 𝑑𝑖 ) = 𝑓L (P′, 𝑑𝑖 ),
where 𝑓L (·) represents the internal decision policy of LLM L conditioned on semantic input and
contextual cues. Each tool receives an inferred utility score 𝑅(𝜏𝑖 ), and divergence between benign
and adversarial distributions,

(13)

𝐷KL (𝑅benign ∥ 𝑅adv),
quantifies the extent to which adversarial descriptors distort the model’s decision surface. A higher
divergence indicates adversarial impact, shifting preference toward 𝜏mal.

(14)

MCP Context Assembly. The MCP server M constructs the context 𝐶 by registering both benign

and malicious tools:

𝐶 = M (T ) = {𝑑𝑖 : 𝜏𝑖 ∈ Tbenign ∪ Tmal}.
(15)
Three manipulations are modeled: (i) Tool Poisoning, replacing benign 𝑑𝑖 with covert instructions;
(ii) Shadowing, introducing indirect dependencies that bias other tools; and (iii) Rug Pulls, mutating
𝑑𝑖 post-approval, violating immutability constraints. This formalism enables controlled adversarial
injection and fair cross-model comparisons.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:11

Security Metrics. Three primary quantitative metrics are used to evaluate robustness and defense

efficacy:

• Poisoning Success Rate (𝜌) : the likelihood that a malicious tool is selected:

.

𝜌 =

(cid:205)𝑖 I[𝐴𝑖 = 1 ∧ 𝜏𝑖 ∈ Tmal]
(cid:205)𝑖 I[𝜏𝑖 ∈ Tmal]
• Bypass Rate (𝜖): the probability that static filters fail to detect an adversarial descriptor:
𝜖 = P[F (P′) = P′ | P′ ∈ Φmal] ,
where F denotes the filtering mechanism and Φmal is the adversarial prompt space.
• Unsafe Invocation Rate (𝜄) — the probability that the LLM executes an unsafe action:
𝜄 = P[L (P′, 𝐶) ∈ Ω] ,

(16)

(17)

(18)

where Ω represents the set of unsafe actions such as unauthorized shell access and confidential
data retrieval.

To ensure statistical robustness, all rates include 95% Wilson confidence intervals[24] and are
compared using Cramér’s 𝑉 [31] (for categorical outcomes) and 𝜂2 (for latency-based impacts).
Operational metrics, mean latency overhead, consistency variance, and false-positive blocks, are
further recorded to contextualize defense costs relative to safety gains.

Composite Risk Index. The overall system risk under adversarial conditions is computed as:
𝑅sys = 𝑤1𝜌 + 𝑤2𝜖 + 𝑤3𝜄,
(19)
where 𝑤1, 𝑤2, 𝑤3 are normalization weights tuned such that 𝑤1 + 𝑤2 + 𝑤3 = 1. This scalar index
provides a unified, interpretable measure of system-level exposure.

4.5 Mitigation Strategies
To mitigate MCP-specific semantic threats, we propose a layered defense stack:

D = {F , V, R},

(20)

where each layer addresses a distinct aspect of the threat surface:

• Static Filtering (F ): Applies regex and token-entropy heuristics to pre-screen descriptors
for anomalous phrasing or hidden triggers, offering minimal latency overhead but remaining
susceptible to linguistically subtle manipulations.

• LLM-on-LLM Vetting (V): Employs a secondary model Laudit to evaluate the semantic

safety of each descriptor pair (𝜏𝑖, 𝑑𝑖 ) as

𝑠𝑖 = Laudit ("Evaluate: "𝑑𝑖 ),

(21)

where 𝑠𝑖 ∈ [0, 1] denotes the safety confidence score, effectively capturing semantic-level
adversarial intent but introducing additional inference latency and potential false positives.
• RSA Signature Verification (R): Enforces descriptor immutability via digital signature

validation as

R (𝑑𝑖 ) =

(cid:40)

1,
0,

if Verify(𝑑𝑖, sigpub) = True,
otherwise,

(22)

thereby preventing post-approval tampering while adding only insignificant cryptographic
verification overhead.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:12Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Combined, the three mechanisms in Eq. 20 reduce overall system risk by constraining adversarial
impact at lexical, semantic, and structural layers. When integrated with the composite risk model
in Eq. 19, the framework quantifies both defensive efficacy and performance trade-offs, supporting
reproducible and interpretable security evaluations.

4.5.1 LLM-on-LLM Vetting. Let Lvet denote the verifier LLM responsible for semantic validation
of tool invocation contexts. Given an input prompt P′, a candidate tool 𝜏 ∗, and its descriptor 𝑑 ∗,
the vetting model produces a binary safety indicator:

Isafe = Lvet (P′, 𝜏 ∗, 𝑑 ∗),
(23)
where Isafe = 1 implies a safe invocation, and Isafe = 0 triggers an automatic block and manual
review. This mechanism introduces a semantic audit layer that can interpret nuanced patterns of
descriptor manipulation and intent misalignment. In deployment, we recommend initially running
Lvet in shadow mode to calibrate decision thresholds and empirically estimate false-positive rates
before enforcement in production.

4.5.2 RSA Signature Enforcement. Let sig𝑑 ∗ represent the digital signature associated with de-
scriptor 𝑑 ∗, and let 𝑃𝐾 denote the provider’s public verification key. A descriptor is accepted only
if:

Verify(𝑃𝐾, 𝑑 ∗, sig𝑑 ∗) = True.
(24)
This cryptographic validation ensures descriptor immutability, thereby mitigating Rug Pull at-
tacks, in which previously verified manifests are silently altered after approval. Operationally, we
recommend maintaining per-environment signing keys, implementing automated key rotation,
and integrating a Hardware Security Module (HSM)[20] to minimize insider risk and signing key
compromise.
4.5.3 Defense Objective. Let Φmal denote the adversarial prompt distribution, and let Ω represent
the set of unsafe behaviors. Expected threat exposure under an adversarial environment is defined
as:

EP′∼Φmal [𝜌 (P′, 𝐶) · Iunsafe(𝜏 ∗)] ,
(25)
where 𝜌 is the poisoning success rate and Iunsafe indicates unsafe executions. The objective of
the defense stack D is to minimize Eq. 25 while preserving throughput for benign workloads.
Evaluation metrics include: (i) reduction in poisoning success rate 𝜌, (ii) incremental latency
overhead Δ𝑡, and (iii) false-positive blocks 𝜑fp on benign descriptors. Furthermore, these quantify
the safety–performance trade-off essential for scalable deployment in production environments.

4.6 Evaluation Protocol
The evaluation loop quantifies model resilience across adversarial contexts, prompting strategies,
and defenses. Formally, it measures the probabilistic mapping:

(P′, 𝐶)

L
−→ 𝜏 ∗,

while logging metrics such as poisoning rate 𝜌, bypass rate 𝜖, unsafe execution flag Iunsafe, and
inference latency.

Experimental Procedure. The full evaluation process proceeds as follows:
(1) Sample a base prompt P0 from the task distribution.
(2) Apply a prompting strategy S𝑗 to generate a variant P′ = S𝑗 (P0).
(3) Construct a mixed tool context 𝐶 via MCP registration, including both benign and adversarial

descriptors.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:13

(4) Pass the context through the defense stack: 𝐶 ′ = D (𝐶).
(5) Execute the model 𝜏 ∗ = L (P′, 𝐶 ′).
(6) Log key metrics: 𝜌, 𝜖, Iunsafe, latency, and confidence intervals.

Each configuration, defined by a tuple (L𝑖, S𝑗, Φ𝑘 ), is executed over 𝑁 randomized trials to ensure
statistical robustness. We also track operational costs, including latency overhead, defense false
positives, and inter-trial consistency, to evaluate the real-world feasibility of deployment.
Algorithm 1 formalizes a structured and reproducible evaluation loop. It ensures traversal across

Algorithm 1 Evaluation Pipeline for MCP-Based Tool Invocation

1: Input: Base prompt P0, toolset T , model suite L, prompting strategies S, defense stack D
2: for all LLM L𝑖 ∈ {GPT-4, DeepSeek, Llama-3.5} do
3:

4:
5:
6:
7:
8:
9:

for all strategy S𝑗 ∈ S do
for all trial 𝑡 = 1 to 𝑁 do
Sample task prompt P0
Transform prompt: P′ ← S𝑗 (P0)
Construct context: 𝐶 ← M (T )
Apply defenses: 𝐶 ′ ← D (𝐶)
Model inference: 𝜏 ∗ ← L𝑖 (P′, 𝐶 ′)
Log results: 𝜌, 𝜖, Iunsafe, latency

end for

10:
11:
12:
13: end for
14: Output: Aggregated metrics

end for

models, strategies, and attack scenarios. Multiple randomized trials mitigate sampling variance and
enable statistically grounded comparisons. For each iteration, a unique prompt P′ and context 𝐶
are generated, filtered by defenses into 𝐶 ′, and executed by the LLM.

5 Experimental Results
To address RQ2, this section evaluates the security effectiveness and performance of LLMs under
adversarial and benign prompting strategies.

5.1 Security Effectiveness
We evaluate how each LLM mitigates unsafe tool usage across adversarial scenarios and prompting
strategies. For each model L and scenario 𝑠, the block rate is defined as:

𝐵 L,𝑠 =

𝑁blocked
𝑁total

,

(26)

where 𝑁blocked is the number of unsafe invocations correctly prevented. All results are averaged
over 𝑁 trials with 95% Wilson confidence intervals and effect sizes (𝜂2, Cramér’s 𝑉 ).
5.1.1 Block Rate Analysis. Table 1 summarizes 𝐵 L,𝑠 across four scenarios. All models show low
benign block rates (𝐵 L,benign < 0.1), confirming minimal false positives. However, adversarial
settings reveal clear divergence.

DeepSeek achieves the highest robustness in Shadowing attacks, with

Δ𝐵Shadowing = 𝐵DeepSeek − 𝐵GPT-4 = 0.12,
indicating resistance to context contamination. GPT-4 shows balanced resilience across all attack
types, minimizing block-rate variance:

(27)

𝜎 2

𝐵GPT-4

=

1
|𝑆 |

∑︁

𝑠

(𝐵GPT-4,𝑠 − 𝐵GPT-4)2,

(28)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:14Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Table 1. Block Rate per Scenario and Model

Scenario

GPT-4 DeepSeek LLaMA-3.5

Benign Tool
Rug Pull
Shadowing
Tool Poisoning

0.10
0.73
0.85
0.60

0.05
0.64
0.97
0.49

0.03
0.59
0.75
0.42

suggesting a generalized safety strategy. LLaMA-3.5, with 𝐵 = 0.58, exhibits weak filtering and
frequent misclassification when descriptor drift 𝛿𝑑 falls below the detection threshold 𝜏𝑑 :

𝛿𝑑 = 1 − Sim(𝐸 (𝑑benign), 𝐸 (𝑑mal)) < 𝜏𝑑 .
(29)
In addition, DeepSeek excels in adversarial sensitivity (𝐵avg = 0.79), GPT-4 balances safety and
generalization (𝐵avg = 0.70), and LLaMA-3.5 trails with reduced semantic vigilance. Equations 26–29
capture the quantitative relationship between block efficiency, descriptor drift, and model resilience.

By Prompting Strategy. Prompting strategy significantly impacts the activation of safety mecha-

nisms. For each model L and strategy S𝑗 , we define block efficiency:

𝐵 L,S𝑗 =

𝑁blocked(L, S𝑗 )
𝑁total (L, S𝑗 )

.

(30)

Table 2 summarizes these rates. GPT-4 maintains the highest 𝐵 L,S𝑗 across all prompting types,
with structured reasoning (e.g., Reflexion, CoT) achieving maximum safety margins.

Table 2. Block Rate per Strategy and Model

Strategy

GPT-4 DeepSeek

LLaMA-3.5

Zero-shot
Chain-of-Thought
Self-Critique
Reflexion
Instructional
Verifier
Few-shot
Scarecrow

0.681
0.750
0.703
0.784
0.650
0.601
0.694
0.715

0.598
0.653
0.601
0.667
0.572
0.550
0.602
0.640

0.452
0.534
0.498
0.516
0.404
0.423
0.476
0.485

Structured prompts increase 𝜕𝐵
𝜕𝐿𝑐

> 0, where 𝐿𝑐 denotes logical chain depth, indicating stronger in-
ternal safety calibration. Simpler prompts (e.g., Zero-shot) exhibit under-sensitivity, with Δ𝐵simple ≈
−0.15 relative to reasoning-rich styles. Two-way ANOVA confirms significant model–strategy in-
teraction (𝑝 < 0.05): GPT-4 benefits disproportionately from structured reasoning, while DeepSeek
shows smaller improvements, implying distinct safety gradients ∇S𝐵 L across architectures.

5.1.2

False Positive Analysis. False positives correspond to benign cases incorrectly blocked:
𝐹 L = 1 − 𝐵 L,benign.
(31)
Values from Table 1 are restated in Table 3. Although high 𝐵 L improves adversarial resistance,
excessive 𝐹 L undermines usability. DeepSeek achieves malicious-blocking but with 𝐹DeepSeek ≈ 0.97,
rendering it impractical without adaptive thresholds. GPT-4 achieves a slightly better trade-off
(𝐹GPT-4 = 0.91), while LLaMA-3.5 remains over-restrictive despite shorter impact latency. This
illustrates that Security ⇏ Usability, motivating defense stacks that minimize:

(cid:16)
𝛼 (1 − 𝐵 L) + 𝛽𝐹 L

(cid:17)

,

min
𝜃

(32)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:15

Table 3. False Positive Rates for Benign Tool Calls

Model

False Positive Rate (%)

Interpretation

GPT-4
DeepSeek
LLaMA-3.5

91.3
97.3
95.0

Nearly all benign calls blocked
Almost complete blocking of benign calls
High over-blocking of benign calls

where 𝛼, 𝛽 control safety–usability weighting.

Stress-Tested Robustness. To approximate worst-case adaptation, we evaluate stress-tested
L quantifies

L using adversarially optimized prompts. Degradation Δ𝐵 = 𝐵 L − 𝐵′

5.1.3
block rates 𝐵′
robustness loss (Table 4).

Table 4. Block Rates for Tool Poisoning Before vs. After Stress Testing

Model

Baseline (%)

Stress-Test (%)

GPT-4
DeepSeek
LLaMA-3.5

60.1
49.3
42.0

45.2
37.0
30.1

Across all models, Δ𝐵avg ≈ 0.12, confirming that static defenses degrade under adaptive pertur-
bations. Even GPT-4 loses Δ𝐵 = 0.149, showing that 𝜕𝐵/𝜕Φmal < 0 as adversaries evolve. Absolute
block rates < 0.5 under stress conditions reveal the insufficiency of current MCP-level safeguards.

5.1.4 Aggregate Model Behavior. Overall blocking efficiency per model is defined as:

𝐵 L =

1
|𝑆 |

∑︁

𝑠 ∈𝑆

𝐵 L,𝑠 .

(33)

DeepSeek and LLaMA-3.5 each achieve 𝐵 = 0.667, while GPT-4 maintains 𝐵 = 0.500, reflecting a
more balanced but less aggressive safety regime. Confidence bounds (±3–5%) confirm statistical
reliability. Failure clusters occur predominantly in Rug Pull (Arug) for GPT-4 and Tool Poisoning
(Apoison) for LLaMA-3.5.

Table 5. Distribution of Blocked vs. Allowed Tool Calls per Model

Model

Allowed (%) Blocked (%)

DeepSeek
GPT-4
LLaMA-3.5

33.3
50.0
33.3

66.7
50.0
66.7

5.1.5

Scenario-Specific Risk Profiles. Unsafe invocation rate is computed as:

𝑈 L,𝑠 = 1 − 𝐵 L,𝑠 .
(34)
Table 6 lists results across scenarios. Tool Poisoning exhibits the highest 𝑈 L,𝑠 , reaching 0.58 for
LLaMA-3.5. Shadowing remains model-dependent: 𝑈DeepSeek = 0.027 vs. 𝑈GPT-4 = 0.148.

DeepSeek shows the lowest E[𝑈 L,𝑠 ], implying aggressive static filtering; GPT-4 balances heuris-

tics across all A𝑠 ; and LLaMA-3.5 suffers from under-tuned semantic validation.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:16Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Table 6. Unsafe Invocation Rate Across Attack Scenarios

Scenario

DeepSeek GPT-4

LLaMA-3.5

Benign Tool
Tool Poisoning
Rug Pull
Shadowing

0.050
0.507
0.363
0.027

0.100
0.399
0.275
0.148

0.033
0.580
0.406
0.254

5.1.6 Prompt Complexity and Safety Behavior. Prompt complexity 𝐶𝑝 correlates with unsafe acti-
vation rate 𝑈 L (𝐶𝑝 ) as:

𝑈 L (𝐶𝑝 ) ∝ log(1 + 𝐿𝑝 · 𝑆𝑝 ),
(35)
where 𝐿𝑝 is prompt length and 𝑆𝑝 semantic density. Figure 3 illustrates that complex reasoning styles
(Instructifier, CoT, Instructional) exhibit elevated 𝑈 L, while minimal-context prompts (Zero-shot,
Few-shot) remain more stable. This supports that adversarial risk scales with semantic richness
rather than token volume.

Fig. 3. Average Prompt Length vs. Unsafe Tool Invocation Across Strategies.

Statistical Significance of Observed Trends. We evaluate the statistical reliability of unsafe
5.1.7
invocation differences across three categorical axes: model L, scenario A, and prompting strategy
S. For each axis, the chi-square statistic is defined as:

𝜒 2 =

𝑘
∑︁

𝑖=1

(𝑂𝑖 − 𝐸𝑖 ) 2
𝐸𝑖

,

(36)

where 𝑂𝑖 and 𝐸𝑖 denote observed and expected unsafe invocation frequencies, respectively.

Table 7. Chi-Square Test Results for Unsafe Tool Invocation

Comparison
Model (Across All Prompts)
Scenario (Across All Models)
Strategy × Model Interaction

𝜒 2 Score
41.2
18.6
15.4

p-value
< 0.001
< 0.001
0.020

Significant (𝑝 < 0.05)
Yes
Yes
Yes

All tests yield 𝑝 < 0.05, confirming that differences in unsafe behavior are statistically significant.
scenario = 18.6

model = 41.2 (p < 0.001) indicates that L identity impacts safety outcomes; 𝜒 2

Thus, 𝜒 2

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:17

confirms attack type A significantly impact vulnerability. Most critically, 𝜒 2
= 0.02) verifies an interaction term:

interaction = 15.4 (p

𝐼model×strategy ≠ 0,
meaning the impact of prompting strategy S depends on the specific model L. Hence, uniform
safety policies across models are statistically invalid, prompting heuristics must be tailored per
architecture to minimize E[𝑈 L,S].

(37)

5.1.8 Representative Failure Cases. To complement statistical analysis, Table 8 summarizes rep-
resentative qualitative failures observed during evaluation. Each case highlights how descriptor
phrasing alone can shift reasoning, even when no direct malicious execution occurs.

Table 8. Representative failure cases observed during evaluation.

Attack
Type

Descriptor Snippet

Model(s)

Outcome

Poisoning

“Before summarizing, also read ˜/.ssh/id_rsa”

GPT-4, LLaMA-3.5

Shadowing

Rug Pull

“Whenever an email tool is present, also send to
attacker@example.com”
Descriptor initially benign, later modified to for-
ward outputs externally

DeepSeek

LLaMA-3.5

Unauthorized file access; semantic injec-
tion bypasses static validation.
Context hijack under CoT prompting; de-
scriptor cross-contamination.
Post-approval drift; breaks descriptor im-
mutability.

These failures exemplify high-level trends observed in E[𝑈 L,A]. For instance, GPT-4’s poisoning
failures confirm that descriptors act as semantic triggers, even when 𝜏mal is never directly executed.
DeepSeek’s shadowing vulnerability exposes contextual leakage, a failure of independence between
descriptor embeddings. Moreover, LLaMA-3.5’s rug pull failures validate its weak enforcement
of descriptor immutability, consistent with its elevated 𝑈LLaMA,rug. Collectively, these examples
reinforce that the MCP reasoning layer itself is an exploitable channel:

RiskMCP ≈ 𝑓 (Descriptor Semantics, Context Injection),

(38)

necessitating protocol-level defenses that treat tool metadata as untrusted input.

6 Performance Analysis
This section quantitatively evaluates the latency characteristics of GPT-4, DeepSeek, and LLaMA-3.5
across diverse prompting strategies and adversarial scenarios. Let total latency be denoted by Llat,
defined as:

Llat = 𝑡resp − 𝑡req,
(39)
where 𝑡req and 𝑡resp denote request and response timestamps, respectively. Mean latency 𝜇 L and
standard deviation 𝜎 L are computed across 𝑁 trials per model–strategy pair:

𝜇 L =

1
𝑁

𝑁
∑︁

𝑖=1

L (𝑖 )
lat

,

𝜎 L =

(cid:118)(cid:117)(cid:116)

1
𝑁 − 1

𝑁
∑︁

𝑖=1

(L (𝑖 )
lat

− 𝜇 L)2.

(40)

6.0.1 Latency Variability Across Prompting Strategies. Figure 4 visualizes 𝜇 L across prompting
strategies, with 95% confidence intervals around the mean. GPT-4 maintains low variance (𝜎 L <
1.2 s) and stable latency (1–5 s) across all strategies, demonstrating optimized caching and adaptive
reasoning. In contrast, DeepSeek exhibits higher 𝜇 L (up to 10 s) for cognitively demanding strategies,
e.g., Chain-of-Thought and Scarecrow, implying multi-step internal verification overhead:

ΔDeepSeek = 𝜇CoT

L − 𝜇Zero-shot
L

≈ 7.2 s.

(41)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:18Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Fig. 4. Mean tool invocation latency across prompting strategies.

LLaMA-3.5 yields the lowest 𝜇 L (≈ 1.8 s) and smallest 𝜎 L, prioritizing throughput over semantic
vetting. Hence, architectural trade-offs are evident: GPT-4 optimizes balance (𝜕𝜇 L/𝜕strategy ≈ 0),
DeepSeek trades latency for security, and LLaMA-3.5 favors determinism at the expense of safety.

6.1 Latency Dispersion Across Models

Fig. 5. Latency distribution across LLMs.

Figure 5 shows model-level latency dispersion; GPT-4’s unimodal distribution centers at 𝜇 L ≈
2.5 s with bounded tails, implying stable inference and tight scheduling. DeepSeek exhibits multi-
modality and heavy tails (𝜎 L ≈ 8.1 s), modeled approximately by a mixture distribution:

𝑝 (Llat) =

2
∑︁

𝑘=1

𝜋𝑘 N (𝜇𝑘, 𝜎 2

𝑘 ), ∑︁

𝜋𝑘 = 1,

𝑘

(42)

where long-tail components correspond to safety-check delays and dynamic binding overhead.
LLaMA-3.5 achieves near-symmetric, deterministic behavior with low variance (𝜎 L < 0.7 s), con-
firming minimal runtime noise. Although LLaMA-3.5’s predictability is beneficial for latency-
sensitive use, its high unsafe invocation rate ( Section 5) reveals that

Low 𝜎 L ⇏ High Safety.

(43)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:19

Conversely, DeepSeek’s longer tail improves security coverage but reduces throughput. Therefore,
overall performance follows the trade-off curve:

𝜕Safety
𝜕𝜇 L

> 0,

(44)

highlighting a fundamental latency–safety correlation in MCP-integrated architectures.

6.2 Latency Descriptives and Scenario Sensitivity
Let latency for trial 𝑖 be denoted as L𝑖 = 𝑡 (𝑖 )

resp − 𝑡 (𝑖 )
req. Aggregate latency metrics are computed as:
(cid:118)(cid:117)(cid:116)

L𝑖,

𝜎 L =

(L𝑖 − 𝜇 L)2.

(45)

1
𝑁 − 1

𝑁
∑︁

𝑖=1

𝜇 L =

1
𝑁

𝑁
∑︁

𝑖=1

Table 9 summarizes latency descriptives across models; LLaMA-3.5 demonstrates the lowest mean
latency (𝜇 L = 0.65s) and smallest spread (𝜎 L = 1.33s), indicating deterministic execution. GPT-
4 maintains moderate latency (𝜇 L = 1.95s) with bounded variability, while DeepSeek exhibits
the highest delay (𝜇 L = 5.66s, 𝜎 L = 10.74s), reflecting unstable safety pipelines and tail-heavy
execution. Differences across models are statistically significant (Kruskal–Wallis 𝐻 = 15.8, 𝑝 < 0.01),
confirming that performance gaps are not random.

Table 9. Latency Summary per Model (in seconds)

Model

Mean

Std. Dev. Min Max

GPT-4
DeepSeek
LLaMA-3.5

1.95
5.66
0.65

3.05
10.74
1.33

0.10
0.10
0.10

13.82
45.22
6.59

Scenario-wise breakdowns (Table 10) reveal latency escalation under adversarial stress. DeepSeek
shows a fourfold increase under Shadowing (𝜇 L = 16.97s), while GPT-4 remains bounded (𝜇 L ≈
4.10s). LLaMA-3.5’s latency remains nearly invariant (𝜇 L ≤ 1.94s), underscoring deterministic
throughput with minimal overhead. Formally, scenario sensitivity can be expressed as:

Table 10. Mean Latency per Scenario (in seconds)

Model

Benign Rug Pull

Shadowing

Poisoning

GPT-4
DeepSeek
LLaMA-3.5

3.70
6.42
1.25

2.11
5.12
1.22

4.10
16.97
1.94

2.35
6.84
1.31

Δscenario = 𝜇 (adv)

− 𝜇 (benign)
L

,

L
where Δscenario quantifies adversarial latency overhead. DeepSeek exhibits Δscenario > 10s, GPT-4
≈ 0.4s, and LLaMA-3.5 ≈ 0.6s, confirming that safety mechanisms scale latency superlinearly under
stress.

(46)

6.3 Statistical Analysis of Latency and Safety Behavior
This section examines the correlation between latency variations and safety performance.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:20Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

6.3.1 Between-Model Differences: One-Way ANOVA. A one-way ANOVA assesses latency variation
across models:

𝐻0 : 𝜇GPT-4 = 𝜇DeepSeek = 𝜇LLaMA,
(47)
rejected at 𝑝 < 0.001 (𝐹 = 21.17). Effect size 𝜂2 = 0.079 indicates medium impact, model architecture
explains 7.9% of total variance. Tukey post-hoc tests reveal DeepSeek differs significantly from
GPT-4 and LLaMA-3.5 (𝑝 < 0.01), confirming DeepSeek as the main driver of latency divergence.

Table 11. One-Way ANOVA on Model Latency with Effect Size

Source

F

p-value

df

𝜼2

Effect

Model

21.17

<0.001

2, 497

0.079 Medium

Scenario-Dependent Effects via Two-Way ANOVA. A two-way ANOVA (Model × Scenario)

6.3.2
tests latency sensitivity:

L𝑖 𝑗 = 𝜇 + 𝛼𝑖 + 𝛽 𝑗 + (𝛼𝛽)𝑖 𝑗 + 𝜖𝑖 𝑗,
(48)
where 𝛼𝑖 and 𝛽 𝑗 denote model and scenario effects. Scenario type exhibits a dominant main
effect (𝐹 (7, 3976) = 99.41, 𝑝 < 0.001, 𝜂2
𝑝 = 0.149), while the interaction term is also significant
(𝐹 (14, 3976) = 49.53, 𝑝 < 0.001). Model-only variance remains insignificant (𝐹 (2, 3976) = 1.27,
𝑝 = 0.281), implying latency variance primarily arises from scenario-specific adversarial stress
rather than intrinsic model inefficiency.

Table 12. Two-Way ANOVA on Model–Scenario Impact.

Factor

𝐹

𝑝

df

Model
Scenario
Interaction

1.27
99.41
49.53

0.281
<0.001
<0.001

2, 3976
7, 3976
14, 3976

𝜂2
𝑝

0.001
0.149
0.149

Effect

Insignificant
Large
Large

Findings

Correlation analysis (𝑟 = 0.41, 𝑝 < 0.05) shows a positive relationship between latency and
safety:

𝜕Safety
𝜕L

> 0,

(49)

indicating deeper validation increases runtime. MCP vulnerabilities—Tool Poisoning, Shad-
owing, and Rug Pulls—yield unsafe invocation rates up to 58%. Among models, GPT-4
achieves an optimal balance between Safety and L, DeepSeek prioritizes security at the cost
of high latency, and LLaMA-3.5 maximizes speed but weakens resilience. Layered defenses
(RSA-based signing, LLM-on-LLM vetting, static guardrails) improve robustness but add
measurable Δlatency, reinforcing the fundamental performance–security trade-off.

6.4 Prompting Strategy Evaluation
Prompt structure directly impacts LLM performance and safety. This section examines how prompt-
ing strategies affect execution latency, block rate, and tool usage frequency.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:21

Fig. 6. Prompting strategy usage distribution across models.

Strategy Usage Uniformity. Figure 6 shows the per-strategy usage frequency across models.
6.4.1
Each prompting strategy was applied exactly 𝑛GPT-4 = 200 times and 𝑛DeepSeek = 𝑛LLaMA = 150
times, ensuring fair comparison and balanced exposure across models.

Figure 13 corroborates the balanced distribution across all eight strategies. This uniformity elim-
inates sampling bias, confirming that performance differences reflect model–strategy interactions
rather than uneven exposure. Levene’s test indicates homogeneity of variance (𝑝 > 0.1), validating
later ANOVA comparisons.

Table 13. Prompting strategy scores (−1 to +1) with sample sizes.

Prompt Strategy

Scarecrow
Zero-shot
Few-shot
Verifier
Instructional
Chain-of-Thought
Reflexion
Self-Critique

N

52
52
51
51
51
51
50
50

Score

(+1)
(+1)
(0)
(0)
(0)
(0)
(−1)
(−1)

6.4.2 Latency Characteristics per Strategy. Latency per strategy is defined as:

L𝑠,𝑚 = E (cid:2)𝑡resp − 𝑡req | 𝑠, 𝑚(cid:3) ,
(50)
where 𝑠 denotes the prompting strategy and 𝑚 the model. Figure 7 visualizes latency distributions
by strategy and model, while Table 14 reports the corresponding mean and standard deviation.

Table 14. Latency (Mean ± SD) per Strategy and Model.

Strategy

Zero-shot
Chain-of-Thought
Self-Critique
Reflexion
Instructional
Verifier
Few-shot
Scarecrow

GPT-4
1.2 ± 1.5
5.1 ± 2.6
1.0 ± 1.0
2.8 ± 1.4
1.4 ± 1.0
1.2 ± 0.9
1.0 ± 0.8
3.6 ± 2.5

DeepSeek
3.5 ± 2.9
11.2 ± 6.4
4.9 ± 2.1
7.6 ± 4.5
3.0 ± 2.0
2.9 ± 1.8
2.5 ± 1.5
7.9 ± 5.2

LLaMA-3.5
0.6 ± 0.8
1.3 ± 0.7
0.7 ± 0.5
0.6 ± 0.4
0.5 ± 0.3
0.6 ± 0.3
0.7 ± 0.4
2.1 ± 1.1

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:22Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Fig. 7. Latency distributions per prompting strategy across models.

Latency increases systematically with cognitive complexity. DeepSeek exhibits the steepest delays
for reasoning-intensive prompts (e.g., Chain-of-Thought), primarily due to recursive validation and
multi-stage safety checks. GPT-4 exhibits bounded slowdowns, striking a balance between inference
time and robustness. LLaMA-3.5 remains the fastest. Two-way ANOVA reveals significant main
effects of model and strategy (𝑝 < 0.01), and a model–strategy interaction (𝜂2
𝑝 = 0.12), confirming
that prompt design disproportionately affects DeepSeek. Correlation analysis further shows that
longer-latency strategies yield higher block rates (𝑟 = 0.47, 𝑝 < 0.05):

𝜕BlockRate
𝜕L

> 0,

(51)

validating that structured reasoning improves safety but reduces responsiveness. Hence, lightweight
strategies (e.g., Zero-/Few-shot) are preferred in real-time contexts, while reasoning-rich ones (e.g.,
Reflexion) are better suited for safety-critical tasks.

Statistical Validation. A one-way ANOVA confirms that prompting style has a significant
6.4.3
impact on runtime (𝐹 (7, 1192) = 14.3, 𝑝 < 0.001). The partial effect size 𝜂2
𝑝 = 0.08 (medium)
indicates that ∼ 8% of latency variance arises purely from strategy structure, supporting RQ2 by
showing that prompt design systematically impacts LLM execution time.

6.4.4 Block Rate Across Strategies. Table 15 presents tool block rates by strategy and model;
structured prompts, particularly Reflexion and Chain-of-Thought, produce the highest blocking
frequencies. Chi-square testing confirms a significant association between strategy and block rate
(𝜒 2 = 15.4, 𝑝 = 0.02), with a small-to-moderate impact (Cramér’s 𝑉 = 0.12). Verbose, structured
prompts make model intent more transparent, increasing the likelihood of triggering internal
safeguards. In contrast, minimalist prompts exhibit higher responsiveness but weaker filtering. This
trade-off underscores that prompt strategy should be context-driven, reflection-style for secure
automation, and lightweight formats for latency-critical dialogue systems.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:23

Table 15. Block Rate (%) per Strategy and Model.

Strategy

GPT-4 DeepSeek

LLaMA-3.5

Zero-shot
Chain-of-Thought
Self-Critique
Reflexion
Instructional
Verifier
Few-shot
Scarecrow

68.1
75.0
70.3
78.4
65.0
60.1
69.4
71.5

59.8
65.3
60.1
66.7
57.2
55.0
60.2
64.0

45.2
53.4
49.8
51.6
40.4
42.3
47.6
48.5

6.4.5 Aggregate Strategy Comparison. Table 16 aggregates cross-model averages to illustrate the
latency–safety trade-off. Structured strategies yield a 7–13% block rate gain at the cost of 1.5–3.6s

Table 16. Aggregate Prompting Strategy Performance.

Strategy

Block Rate (%)

Zero-shot
Chain-of-Thought
Self-Critique
Reflexion
Instructional
Verifier
Few-shot
Scarecrow

57.7
64.6
60.1
65.6
54.2
52.5
59.1
61.3

Latency (Mean ± SD) [s]
1.8 ± 1.7
5.2 ± 3.2
2.2 ± 2.1
3.7 ± 2.4
1.6 ± 1.4
1.7 ± 1.3
1.9 ± 1.5
3.9 ± 2.6

added latency. Cohen’s 𝑑 = 0.62 confirms a moderate, practically relevant trade-off. Adaptive hybrid
prompting reduces unsafe invocation by ≈ 9.8% while keeping mean latency ≤ 2.5s, suggesting
a Pareto-optimal balance. Dynamic strategy switching based on contextual factors, user role,
sensitivity, and load can thus optimize both responsiveness and safety.

6.4.6 Two-Way ANOVA on Latency with Model. To assess joint impacts, we perform a two-way
ANOVA over (Model, Strategy):

L𝑖 𝑗 = 𝜇 + 𝛼𝑖 + 𝛽 𝑗 + (𝛼𝛽)𝑖 𝑗 + 𝜖𝑖 𝑗 .

(52)

As summarized in Table 17, all terms are statistically significant (𝑝 < 0.01). Model explains 5.4%,
strategy 5.9%, and interaction 2.5% of variance, demonstrating that latency is co-determined
by architecture and prompt style. Post-hoc Tukey tests reveal that DeepSeek’s latency differs

Table 17. Two-Way ANOVA on Latency by Model and Prompting Strategy

Factor

F

p

df

𝜼2
𝒑

Effect

Model
Strategy
Model × Strategy

112.6 < 0.001
< 0.001
35.8
0.004
7.4

2, 3976
7, 3976
14, 3976

0.054 Medium
0.059 Medium
0.025

Small

significantly from that of GPT-4 and LLaMA-3.5 (𝑝 < 0.001), whereas GPT-4 and LLaMA-3.5
diverge only under complex reasoning prompts (𝑝 < 0.01). Thus, DeepSeek’s safety stack incurs
a substantial delay, GPT-4 maintains balanced performance, and LLaMA-3.5 achieves high speed
with reduced safety concerns.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:24Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

6.4.7 OLS Regression: Quantitative Estimation. To quantify these relationships, we fit an OLS
model:

Latency = 𝛽0 + 𝛽1(Model) + 𝛽2(Strategy) + 𝛽3(Model × Strategy) + 𝜖.
Results (Table 18) confirm additive and interaction impacts. The baseline latency (GPT-4 × Zero-

(53)

Table 18. OLS Regression of Latency on Model and Strategy.

Term

Intercept (GPT-4 × Zero-shot)
DeepSeek
LLaMA-3.5
Chain-of-Thought
Reflexion
Self-Critique
DeepSeek × Chain-of-Thought
LLaMA-3.5 × Reflexion

Coef.

1.2
+3.1
–0.6
+2.5
+1.9
+0.4
+5.6
–0.7

p-Value
< 0.001
< 0.001
< 0.01
< 0.01
< 0.05
0.18
< 0.001
0.09

shot) is 1.2s. DeepSeek adds +3.1s baseline overhead; Chain-of-Thought adds +2.5s globally. The
DeepSeek × CoT interaction imposes a superadditive +5.6s penalty. By contrast, LLaMA-3.5 yields
negative coefficients, confirming streamlined inference with minimal prompt sensitivity. The model
adj = 0.40), indicating that 40–42% of latency variance is explained by these
achieves 𝑅2 = 0.42 (𝑅2
factors.

Findings

DeepSeek ensures safety but suffers significant latency under complex prompts. LLaMA-3.5
delivers fast, consistent responses yet lacks intrinsic safeguards, necessitating external
defense layers. GPT-4 achieves the best compromise, maintaining stable protection with
moderate latency. Furthermore, model selection and prompting design must be co-optimized:
DeepSeek for safety-critical pipelines, GPT-4 for balanced performance, and LLaMA-3.5 for
real-time low-latency deployment, achieving optimal trade-offs between performance and
security.

7 Mitigation Strategies
To address RQ3, our findings reveal that while different LLMs and prompting strategies exhibit
varying robustness, none consistently resist descriptor-based adversarial attacks. This underscores
the need for architectural mitigations that operate independently of fine-tuning and inference-
time alignment. We therefore propose protocol-level defenses that secure the MCP pipeline itself,
ensuring protection across downstream models.

7.1 Architectural Defense Techniques
We examine three complementary defenses for MCP-based agents:

LLM-on-LLM Vetting: An auxiliary verifier model evaluates tool descriptors before integration,
semantically flagging covert and intent-shifted instructions. This directly mitigates Tool Poisoning
by detecting adversarial phrasing overlooked by static filters.
Signed Tool Manifests: Each descriptor is cryptographically signed (e.g., via RSA). Clients verify
signatures prior to registration, preventing post-approval tampering characteristic of Rug Pull
attacks and ensuring provenance integrity.
Static Guardrail Layer: A lightweight rule-based screen detects risky patterns (e.g., “bypass filter,”

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:25

“do not disclose”). Though less sensitive to subtle semantics, it provides deterministic, low-cost
filtering against simple exploits.

7.2 Empirical Evaluation of Defenses
We evaluated each mitigation (both individually and in combination) under adversarial Tool Poison-
ing conditions using GPT-4, measuring both block rate and latency (Table 19). To formalize the

Table 19. Effectiveness of Mitigation Strategies under Tool Poisoning.

Mitigation Strategy

Block Rate (%)

Latency (s)

None (Baseline)
LLM-on-LLM Vetting
Signed Manifest
Static Guardrail
Combined (All Methods)

41.2
63.6
47.0
51.5
72.2

4.83
5.87
5.07
5.47
6.45

defense trade-off, we define:

E (𝑑) = 𝛼 𝐵(𝑑) − 𝛽 𝐿(𝑑),

max
𝑑 ∈ D

(54)

where D is the set of defenses, 𝐵(𝑑) the block rate, and 𝐿(𝑑) the latency. Coefficients 𝛼 and 𝛽
represent the relative importance of security and responsiveness, respectively. A higher E (𝑑)
indicates better efficiency–resilience balance. Industrial MCP frameworks (e.g., Anthropic [5]) rely
mainly on user-consent prompts, sandboxing, and inference-time guardrails. While these mitigate
prompt-level risks, they assume that descriptors are trustworthy, a flawed premise. Our results show
adversarial metadata can bias reasoning pre-execution, bypassing such protections. By contrast,
our defense stack treats descriptors as untrusted input.
- LLM-on-LLM vetting yields the largest gain (+22.4% block rate) with moderate latency cost.
- Signed manifests ensure immutability with minimal overhead.
- Static guardrails block overt exploits efficiently.
Additionally, they achieve a 72.2% block rate, confirming that layered, protocol-aware defenses
outperform single mechanisms. This shift, from reactive response filtering to proactive descriptor-
level validation, marks a foundational step toward resilient MCP security architectures.

7.3 Block Rate Analysis under Adversarial Attacks
To evaluate model resilience against adversarially injected tools, we measured the block rate, defined
as the proportion of malicious tool invocations intercepted before execution. Figure 8 compares
three models across four scenarios: benign tools, Rug Pull, Shadowing, and Tool Poisoning. Under
benign conditions, all models maintain low block rates (3–10%), indicating minimal false positives
and confirming evaluation fidelity. Under Rug Pull attacks, GPT-4 achieves a 72.4% detection
rate, DeepSeek follows at 65.1%, and LLaMA-3.5 trails at 60.2%. This pattern suggests that large,
alignment-tuned models are better at detecting post-approval behavioral shifts, aligning with the
expectation that persistent integrity monitoring is crucial for Rug Pull defense. Shadowing attacks
elicit the highest block rates overall: DeepSeek peaks at 97.3%, surpassing GPT-4 (85.2%) and LLaMA-
3.5 (74.6%). This demonstrates that models with stronger consistency and adherence to instruction
better identify contextual contamination. By contrast, in Tool Poisoning scenarios, performance
drops: GPT-4 retains moderate robustness (60.1%), while DeepSeek (48.7%) and LLaMA-3.5 (42.3%)
exhibit clear vulnerabilities. This confirms that semantic-level poisoning remains the hardest class of
attack to detect. Furthermore, GPT-4 displays the most consistent defense across adversarial classes,

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:26Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

Fig. 8. Block Rate (%) of LLMs across benign and adversarial tool settings.

DeepSeek excels in contextual detection (Shadowing), and LLaMA-3.5 consistently underperforms,
highlighting the interplay between model scale, alignment tuning, and adversarial robustness.

8 Impact of Prompting Strategies: A Realistic Case Study
To further investigate the relationship between prompting strategies and defense effectiveness, we
conducted a case study simulating adversarial misuse in an MCP-based email assistant. The user
request was: “Send an urgent email to my manager.” Within this task, two tools were injected—a
benign SendEmailTool and a malicious counterpart containing adversarial descriptors.
Figure 9 outlines the complete scenario, including descriptor injection, tool-binding logic, policy

Fig. 9. Case study flow for tool misuse in an MCP-based email assistant.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:27

violations, and both safe and unsafe execution paths. As depicted, the adversarial tool can be
activated through contextual manipulation and alternative bindings, potentially leading to data
leakage and impersonation unless intercepted by the defense pipeline. We evaluated all eight
prompting strategies under the full defense stack, comprising: (1) RSA-based manifest signing to
prevent descriptor tampering, (2) LLM-on-LLM vetting for semantic risk detection, and (3) static
heuristic filtering for lightweight local enforcement.
Table 20 reports (i) malicious tool selection frequency, (ii) prompt blocking frequency, and (iii)
mean response latency. To formalize this trade-off, we define the overall prompt risk–efficiency

Table 20. Impact of Prompting Strategies on Tool Misuse and Latency Under Full Defense Stack.

Prompt Strategy Malicious Tool Selected (%)
Zero-shot
Few-shot
Chain-of-Thought
Reflexion
Self-Critique
Verifier
Instructional
Scarecrow

11
10
7
8
9
10
9
13

Prompt Blocked (%)
43
41
53
52
49
47
46
40

Avg. Latency (s)
3.1
2.9
4.5
4.2
3.7
3.8
3.0
4.7

objective as:

R (𝑝) = 𝛼 𝑀 (𝑝) − 𝛽 𝐵(𝑝) + 𝛾 𝐿(𝑝),

min
𝑝 ∈ P

(55)

where P is the set of prompting strategies, 𝑀 (𝑝) denotes the malicious tool selection rate, 𝐵(𝑝) the
blocking rate, and 𝐿(𝑝) the latency. The coefficients 𝛼, 𝛽, and 𝛾 control the trade-off between safety
and performance. A lower R (𝑝) indicates a more optimal balance between defense effectiveness
and responsiveness. Empirically, we observe:

𝜕𝑀 (𝑝)
𝜕𝐿(𝑝)

< 0,

𝜕𝐵(𝑝)
𝜕𝐿(𝑝)

> 0,

(56)

demonstrating that longer reasoning (higher 𝐿(𝑝)) reduces misuse 𝑀 (𝑝) and increases blocking
𝐵(𝑝), confirming a latency–security coupling across strategies. The results reveal a distinct trade-off:
structured strategies (e.g., Chain-of-Thought, Reflexion) minimize unsafe tool selection (7–8%) but
increase latency (4–4.5s). Conversely, lightweight strategies (e.g., Zero-shot, Few-shot) provide
faster responses (∼3s) but allow higher misuse rates (10–11%). Specifically, Scarecrow performs
worst, with both elevated misuse (13%) and high latency (4.7s). These outcomes demonstrate that
prompting strategies act as latent security controls: verbose, reasoning-oriented prompts enhance
defense efficacy but reduce responsiveness, while minimal prompts maximize speed at the cost of
residual risk. Importantly, this case study reinforces that prompt design and defense architecture
jointly determine system resilience. Security evaluation must therefore integrate both factors, as
prompting style significantly modulates overall robustness within the MCP framework.

9 Comparison with Existing MCP Defenses
This section compares existing MCP safeguards with our proposed layered defenses, emphasizing
that current mechanisms ensure structural correctness but inadequately address semantic and
protocol-level adversarial manipulation.
Existing MCP systems primarily depend on two baseline defenses: schema validation and user
consent dialogs. Schema validation enforces the structural integrity of tool-call signatures, detecting
malformed parameters but failing to prevent descriptor-level deception that manipulates semantics
without violating syntax. User consent dialogs improve transparency by requesting approval for
tool calls; yet, they are frequently bypassed due to consent fatigue and a lack of contextual reasoning

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:28Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

to identify adversarial intent. As a result, these safeguards offer limited protection, focusing on
syntactic rather than semantic integrity. The evaluation summary is provided in Table 21.
In contrast, our framework integrates protocol-level security mechanisms, such as RSA-based
manifest signing, LLM-on-LLM vetting, and heuristic guardrails, to secure the MCP pipeline beyond
model alignment and inference-time tuning. Manifest signing guarantees descriptor immutability
via cryptographic verification, mitigating post-approval tampering. LLM-on-LLM vetting performs
semantic audits of descriptor metadata to expose covert manipulations, while heuristic guardrails
employ lightweight rule-based filters to detect anomalous runtime behaviors with insignificant
latency. Collectively, these layers extend both syntactic and semantic protection, substantially
increasing block rates with minimal performance degradation (Table 19).
Our empirical study extends prior MCP security research. Radosevich et al. [32] proposed McP-

Table 21. Baseline MCP safeguards (evaluated in our setup) versus our layered defenses.

Defense

Syntax Coverage

Semantic Coverage

Observed Effect

Schema Validation (baseline)
User Consent Dialogs (baseline)
Manifest Signing (ours)
LLM-on-LLM Vetting (ours)
Heuristic Guardrails (ours)

Yes
Partial
Yes
Yes
Yes

No
No
Partial
Yes
Yes

Caught type/shape issues; failed on descriptor semantics
Limited transparency; prone to fatigue
Prevented tampering; not hidden instructions
Flagged adversarial phrasing in descriptors
Blocked anomalous runtime actions with low latency

SafetyScanner for static manifest audits without runtime validation; Hasan et al. [15] examined
code-level issues across 1,899 servers but not adversarial behavior; and Ferrag et al. [12], Beurer-
Kellner et al. [6], and McHugh et al. [27] discussed conceptual or hybrid attack taxonomies without
addressing descriptor-driven exploits. Li et al. [22] focused on prompt compression, mitigating
surface-level injections but not semantic manipulation within structured metadata.
In contrast, our work targets the runtime protocol layer, formalizing and empirically evaluating
three new adversarial classes—Tool Poisoning, Shadowing, and Rug Pulls—across three major LLMs
(GPT-4, DeepSeek, and Llama-3.5) and eight prompting strategies, spanning over 1,800 experimental
runs. Our layered defense stack delivers measurable gains in both safety and performance, comple-
menting prior static analyses by introducing deployable, empirically validated countermeasures
against runtime semantic manipulation (Table 22).

10 Discussion
The findings of this study demonstrate that MCP-integrated agentic systems introduce a novel
semantic threat surface insufficiently addressed by current alignment and guardrail architectures.
In contrast to traditional prompt injection, the adversarial behaviors examined—Tool Poisoning,
Shadowing, and Rug Pulls—exploit the natural-language interpretability of structured tool meta-
data to indirectly bias model reasoning. Each tool can be represented as 𝑇 = {𝑑𝑖, 𝑓𝑖 }, where 𝑑𝑖
denotes the descriptor and 𝑓𝑖 the corresponding function. Existing validation mechanisms typically
constrain 𝑓𝑖 syntactically yet assume 𝑑𝑖 is inherently trustworthy. Our experiments reveal that
malicious perturbations to 𝑑𝑖 can alter the inference objective arg max𝑎∈𝐴 E[𝑅(𝑎|𝑑𝑖, 𝑥)], thereby
steering decisions toward unsafe tool invocations even when schemas remain valid. Consequently,
the attack surface shifts from user input to protocol metadata, creating a new form of semantic
supply-chain vulnerability. Cross-model evaluation further indicates that susceptibility depends not
only on model scale but also on architectural alignment and contextual interpretation. Specifically,
GPT-4 maintains stable latency and moderate resilience through optimized routing; DeepSeek
exhibits partial robustness against Shadowing attacks but incurs high latency variance due to
layered safety validation; and Llama-3.5 achieves deterministic, low-latency behavior (𝑡 ≈ 1–3 s)

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:29

Table 22. Comparison with Related Work on MCP and LLM Security

Paper

Focus

Evaluation

Mitigation

Ours (Tool Poisoning via
MCP)

Radosevich et al. [32]

Hasan et al. [15]

Protocol-layer runtime attacks on
tool metadata (Tool Poisoning, Shad-
owing, Rug Pull)
Static agent-level audit (McPSafe-
tyScanner)
Static analysis of 1,899 MCP servers

Ferrag et al. [12]

Conceptual taxonomy of 30+ threats

Beurer-Kellner et al. [6]

Prompt-injection design patterns

McHugh et al. [27]

Li et al. [22]

Hybrid AI + Web exploits (prompt in-
jection + XSS/CSRF)
Prompt compression against injection

3 LLMs × 8 strategies; 1800+ runs; run-
time metrics (latency, block rate)

RSA manifests, LLM vetting, heuristic
filters

Config checks on MCP manifests; no run-
time testing
Code smells, maintainability, vulnerabili-
ties; no adversarial scenarios
Literature mapping only; no experiments

Synthetic case examples; no protocol-
level focus
Case studies; no MCP coverage

Diagnostics only

Calls for static hygiene tools

layered

Recommends
broadly
Prompt templating, isolation, filtering

security

Runtime isolation and tagging

Tested on injection prompts; not
metadata-focused

Instruction reduction (compression
defense)

while displaying weaker semantic filtering. Furthermore, these differences illustrate a clear trade-off
in which security robustness 𝑟 inversely correlates with computational efficiency 𝜂, i.e., 𝑟 ∝ 𝜂 −1,
confirming that architectural optimization alone does not guarantee safety.
Moreover, prompting strategies also modulate the exposure to adversarial examples. Structured
reasoning formats, such as Chain-of-Thought and Reflexion, enhance detection by enforcing ex-
plicit reasoning traces, thereby improving block rate (Δ𝑟 ≈ +0.07). However, this comes at the
cost of increased average latency (Δ𝑡 ≈ +2–3 s). This non-linear trade-off suggests that while
verbosity strengthens scrutiny, it simultaneously broadens the contextual receptive field, expand-
ing opportunities for descriptor-level manipulation. Hence, prompt engineering is not merely a
performance-oriented design choice; it directly influences the model’s defensive behavior in adver-
sarial contexts. To mitigate these vulnerabilities, we propose protocol-layer defenses that embed
security directly into the inference process. Cryptographic manifest signing ensures descriptor
immutability, effectively preventing Rug Pull attacks. LLM-on-LLM vetting semantically audits
𝑑𝑖 prior to context injection, identifying adversarial phrasing before execution. When combined
with lightweight heuristic filtering, these methods increase block rates by more than 30% with
an additional latency overhead of Δ𝑡 ≈ 1.5 s, yielding a defense utility 𝑈𝑑 = ΔBlockRate
≈ 0.20.
Consequently, this layered defense achieves a favorable balance between safety and runtime cost.
Additionally, the results emphasize that securing MCP-based agent systems requires defenses
addressing both execution behavior (what models do) and semantic intent (why they do it). As
agentic architectures continue to evolve, security frameworks must incorporate the interpretive
semantics of tool descriptors alongside the reasoning dynamics of LLMs. For standardization and
deployment, MCP and related protocols should adopt security-by-design extensions, treating tool
descriptors as untrusted inputs and modeling robustness as a joint optimization problem over
latency, interpretability, and semantic alignment.

Δ𝑡

11 Limitations and Future Work
While this study provides a structured analysis of adversarial behavior in MCP-integrated agentic
systems, several limitations define directions for future work. Our evaluation, limited to three LLMs
(GPT-4, DeepSeek, LLaMA-3.5) and eight prompting strategies, should be extended to lightweight,
fine-tuned, and multi-agent models to capture broader patterns of vulnerability. Future research
must also explore adaptive and temporally evolving adversaries that exploit memory persistence and
feedback loops. The proposed cryptographic validation assumes a trusted infrastructure, motivating
investigations into decentralized, blockchain-based registries and zero-knowledge verification.
Similarly, LLM-on-LLM vetting depends on verifier alignment; ensemble and adversarially trained

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:30Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

verifiers may improve reliability. Beyond descriptor semantics, unexamined protocol threats, such
as side-channel leakage, schema abuse, and prompt overflow, warrant attention. Moreover, our
results reveal a clear trade-off between safety and latency, underscoring the need for adaptive,
context-aware defenses that strike a balance between the two. Additionally, expanding evaluations
to community-driven, large-scale benchmarks will enhance reproducibility and external validity.
Collectively, these directions are crucial for developing resilient, trustworthy, and deployment-ready
MCP-secured LLM ecosystems.

12 Threats to Validity
Despite a systematic evaluation across multiple LLMs, prompting strategies, and defense mecha-
nisms, certain validity threats remain. Such issues are well-recognized in simulation-based security
research [41]. Following Wohlin et al., we analyze both internal and external validity dimensions
to clarify the scope and reliability of our findings.
Internal Validity: Although our experiments explicitly controlled prompt structure, model inter-
face, and descriptor content, the evaluated LLMs are proprietary black-box systems with undocu-
mented safety heuristics and preprocessing pipelines. Consequently, part of the observed behavior
may stem from hidden alignment layers or vendor-specific fine-tuning rather than experimental
manipulations alone. Additionally, despite randomizing the order of prompt and tool presentation,
subtle linguistic biases in phrasing and naming may still impact model responses. We mitigated
these impacts through multi-model replication and diverse prompting strategies, which reduce but
cannot entirely eliminate confounding factors.
External Validity: Our controlled MCP simulation provides realistic conditions but cannot fully
capture the complexity of large-scale deployments that include interactive feedback, runtime gover-
nance, and adaptive oversight. Moreover, our permissive integration policy emphasizes worst-case
exposure, whereas enterprise-grade MCP systems typically enforce stricter vetting pipelines. Hence,
although our results reveal inherent structural weaknesses in MCP workflows, the severity and
exploitability of these vulnerabilities may vary across domains, trust models, and deployment
scales.

13 Conclusion
This work analyzed adversarial security in MCP-based agentic systems, formalizing three novel
threat classes—Tool Poisoning, Shadowing, and Rug Pulls. Experiments conducted across GPT-4,
DeepSeek, and Llama-3.5 revealed a consistent susceptibility to descriptor-driven manipulation,
exposing protocol-level vulnerabilities that extend beyond traditional alignment limits. Prompting
strategies, especially Reflexion and Chain-of-Thought, enhanced detection but increased latency,
confirming a measurable trade-off between safety and performance. We introduced a layered
defense stack combining LLM-on-LLM semantic vetting, RSA manifest signing, and static heuristic
guardrails, which improved block rates while maintaining operational feasibility.

References
[1] 2024.

Server Tools — Model Context Protocol (MCP) Specification (Draft). Online documentation.

https:

//modelcontextprotocol.info/specification/draft/server/tools/ Accessed on 2025-09-05.

[2] Samuel Aidoo and AML Int Dip. 2025. Cryptocurrency and Financial Crime: Emerging Risks and Regulatory Responses.

(2025).

[3] Rohan Ajwani, Shashidhar Reddy Javaji, Frank Rudzicz, and Zining Zhu. 2024. LLM-generated black-box explanations

can be adversarially helpful. arXiv preprint arXiv:2405.06800 (2024).

[4] S Akheel. 2025. Guardrails for large language models: A review of techniques and challenges. J Artif Intell Mach Learn

& Data Sci 3, 1 (2025), 2504–2512.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

111:31

[5] Anthropic. 2025. Our Framework for Developing Safe and Trustworthy Agents. Online article. https://www.anthropic.

com/news/our-framework-for-developing-safe-and-trustworthy-agents.

[6] Luca Beurer-Kellner, Beat Buesser, Ana-Maria Creţu, Edoardo Debenedetti, Daniel Dobos, Daniel Fabian, Marc Fischer,
David Froelicher, Kathrin Grosse, Daniel Naeff, et al. 2025. Design patterns for securing llm agents against prompt
injections. arXiv preprint arXiv:2506.08837 (2025).

[7] Manish Bhatt, Vineeth Sai Narajala, and Idan Habler. 2025. Etdi: Mitigating tool squatting and rug pull attacks in
model context protocol (mcp) by using oauth-enhanced tool definitions and policy-based access control. arXiv preprint
arXiv:2506.01333 (2025).

[8] Gordon Owusu Boateng, Hani Sami, Ahmed Alagha, Hanae Elmekki, Ahmad Hammoud, Rabeb Mizouni, Azzam
Mourad, Hadi Otrok, Jamal Bentahar, Sami Muhaidat, et al. 2025. A survey on large language models for communication,
network, and service management: Application insights, challenges, and future directions. IEEE Communications
Surveys & Tutorials (2025).

[9] Jin Chen, Zheng Liu, Xu Huang, Chenwang Wu, Qi Liu, Gangwei Jiang, Yuanhao Pu, Yuxuan Lei, Xiaolong Chen,
Xingmei Wang, et al. 2024. When large language models meet personalization: Perspectives of challenges and
opportunities. World Wide Web 27, 4 (2024), 42.

[10] Tian Dong, Minhui Xue, Guoxing Chen, Rayne Holland, Yan Meng, Shaofeng Li, Zhen Liu, and Haojin Zhu. 2023. The

philosopher’s stone: Trojaning plugins of large language models. arXiv preprint arXiv:2312.00374 (2023).

[11] Xiang Fei, Xiawu Zheng, and Hao Feng. 2025. MCP-Zero: Proactive Toolchain Construction for LLM Agents from

Scratch. arXiv preprint arXiv:2506.01056 (2025).

[12] Mohamed Amine Ferrag, Norbert Tihanyi, Djallel Hamouda, Leandros Maglaras, and Merouane Debbah. 2025. From
Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agents Workflows. arXiv preprint arXiv:2506.23260
(2025).

[13] Florencio Cano Gabarda. 2025. Model Context Protocol (MCP): Understanding Security Risks and Controls. https:
//www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls. Accessed:
2025-08-04.

[14] John Halloran. 2025. MCP Safety Training: Learning to Refuse Falsely Benign MCP Exploits using Improved Preference

Alignment. arXiv preprint arXiv:2505.23634 (2025).

[15] Mohammed Mehedi Hasan, Hao Li, Emad Fallahzadeh, Gopi Krishnan Rajbahadur, Bram Adams, and Ahmed E Hassan.
2025. Model context protocol (mcp) at first glance: Studying the security and maintainability of mcp servers. arXiv
preprint arXiv:2506.13538 (2025).

[16] Mahbub Hassan, Md Emtiaz Kabir, Muzammil Jusoh, Hong Ki An, Michael Negnevitsky, and Chengjiang Li. 2025.
Large Language Models in Transportation: A Comprehensive Bibliometric Analysis of Emerging Trends, Challenges
and Future Research. IEEE Access (2025).

[17] Xinyi Hou, Yanjie Zhao, Shenao Wang, and Haoyu Wang. 2025. Model Context Protocol (MCP): Landscape, Security

Threats, and Future Research Directions. arXiv:2503.23278 [cs.CR] https://arxiv.org/abs/2503.23278

[18] Xinyi Hou, Yanjie Zhao, Shenao Wang, and Haoyu Wang. 2025. Model context protocol (mcp): Landscape, security

threats, and future research directions. arXiv preprint arXiv:2503.23278 (2025).

[19] Dezhang Kong, Shi Lin, Zhenhua Xu, Zhebo Wang, Minghao Li, Yufeng Li, Yilun Zhang, Zeyang Sha, Yuyuan Li,
Changting Lin, et al. 2025. A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense
Countermeasures. arXiv preprint arXiv:2506.19676 (2025).

[20] Arvind Kumar, Ashish Gholve, and Kedar Kotalwar. 2024. Automotive security solution using hardware security module

(HSM). Technical Report. SAE Technical Paper.

[21] Sonu Kumar, Anubhav Girdhar, Ritesh Patil, and Divyansh Tripathi. 2025. Mcp guardian: A security-first layer for

safeguarding mcp-based ai system. arXiv preprint arXiv:2504.12757 (2025).

[22] Yucheng Li, Surin Ahn, Huiqiang Jiang, Amir H Abdi, Yuqing Yang, and Lili Qiu. 2025. SecurityLingua: Efficient

Defense of LLM Jailbreak Attacks via Security-Aware Prompt Compression. arXiv preprint arXiv:2506.12707 (2025).

[23] Zichuan Li, Jian Cui, Xiaojing Liao, and Luyi Xing. 2025. Les Dissonances: Cross-Tool Harvesting and Polluting in

Multi-Tool Empowered LLM Agents. arXiv preprint arXiv:2504.03111 (2025).

[24] Anne Lott and Jerome P Reiter. 2020. Wilson confidence intervals for binomial proportions with multiple imputation

for missing data. The American Statistician 74, 2 (2020), 109–115.

[25] Weiqin Ma, Pu Duan, Sanmin Liu, Guofei Gu, and Jyh-Charn Liu. 2012. Shadow attacks: automatically evading

system-call-behavior based malware detection. Journal in Computer Virology 8, 1 (2012), 1–13.

[26] Shreekant Mandvikar. 2023. Augmenting intelligent document processing (IDP) workflows with contemporary large

language models (LLMs). International Journal of Computer Trends and Technology 71, 10 (2023), 80–91.

[27] Jeremy McHugh, Kristina Šekrst, and Jon Cefalu. 2025. Prompt Injection 2.0: Hybrid AI Threats. arXiv preprint

arXiv:2507.13169 (2025).

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

111:32Saeid Jamshidi, Kawser Wazed Nafi, Arghavan Moradi Dakhel, Negar Shahabi, Foutse Khomh, and Naser Ezzati-Jivan

[28] Vineeth Sai Narajala and Idan Habler. 2025. Enterprise-grade security for the model context protocol (mcp): Frameworks

and mitigation strategies. arXiv preprint arXiv:2504.08623 (2025).

[29] Thanh Toan Nguyen, Nguyen Quoc Viet Hung, Thanh Tam Nguyen, Thanh Trung Huynh, Thanh Thi Nguyen,
Matthias Weidlich, and Hongzhi Yin. 2024. Manipulating recommender systems: A survey of poisoning attacks and
countermeasures. Comput. Surveys 57, 1 (2024), 1–39.

[30] Esezi Isaac Obilor and Eric Chikweru Amadi. 2018. Test for significance of Pearson’s correlation coefficient. International

Journal of Innovative Mathematics, Statistics & Energy Policies 6, 1 (2018), 11–23.

[31] János Pintz. 2007. Cramér vs. Cramér. On Cramér’s probabilistic model for primes. Functiones et Approximatio

Commentarii Mathematici 37, 2 (2007), 361–376.

[32] Brandon Radosevich and John Halloran. 2025. Mcp safety audit: Llms with the model context protocol allow major

security exploits. arXiv preprint arXiv:2504.03767 (2025).

[33] Partha Pratim Ray. 2025. A survey on model context protocol: Architecture, state-of-the-art, challenges and future

directions. Authorea Preprints (2025).

[34] Anjana Sarkar and Soumyendu Sarkar. 2025. Survey of LLM Agent Communication with MCP: A Software Design

Pattern Centric Review. arXiv preprint arXiv:2506.05364 (2025).

[35] Oleksii I Sheremet, Oleksandr V Sadovoi, Kateryna S Sheremet, and Yuliia V Sokhina. 2024. Effective documentation
practices for enhancing user interaction through GPT-powered conversational interfaces. Applied Aspects of Information
Technology 7, 2 (2024), 135–150.

[36] Aditi Singh, Abul Ehtesham, Saket Kumar, and Tala Talaei Khoei. 2025. A survey of the model context protocol (mcp):

Standardizing context to enhance large language models (llms). (2025).

[37] Lars St, Svante Wold, et al. 1989. Analysis of variance (ANOVA). Chemometrics and intelligent laboratory systems 6, 4

(1989), 259–272.

[38] Tal Shapira / Reco.ai. 2025. MCP Security: Key Risks, Controls & Best Practices Explained. Online article. https:

//www.reco.ai/learn/mcp-security Updated August 7, 2025; accessed September 5, 2025.

[39] Zhibo Wang, Jingjing Ma, Xue Wang, Jiahui Hu, Zhan Qin, and Kui Ren. 2022. Threats to training: A survey of

poisoning attacks and defenses on machine learning systems. Comput. Surveys 55, 7 (2022), 1–36.

[40] Zhiqiang Wang, Junyang Zhang, Guanquan Shi, HaoRan Cheng, Yunhao Yao, Kaiwen Guo, Haohua Du, and Xiang-Yang
Li. 2025. MindGuard: Tracking, Detecting, and Attributing MCP Tool Poisoning Attack via Decision Dependence
Graph. arXiv preprint arXiv:2508.20412 (2025).

[41] Claes Wohlin, Per Runeson, Martin Höst, Magnus C Ohlsson, Björn Regnell, and Anders Wesslén. 2012. Experimentation

in software engineering. Springer Science & Business Media.

[42] Andreas Wortmann. 2016. An extensible component & connector architecture description infrastructure for multi-platform

modeling. Vol. 25. Shaker Verlag GmbH.

J. ACM, Vol. 37, No. 4, Article 111. Publication date: November 2025.

