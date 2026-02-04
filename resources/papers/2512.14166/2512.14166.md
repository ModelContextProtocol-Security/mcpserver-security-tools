IntentMiner: Intent Inversion Attack via Tool Call Analysis in the Model
Context Protocol

Yunhao Yao1,†, Zhiqiang Wang1,†, Haoran Cheng1, Yihang Cheng1, Haohua Du2, Xiang-Yang Li1
1 University of Science and Technology of China, Hefei, China
2 Beijing University of Aeronautics and Astronautics, Beijing, China
yaoyunhao@mail.ustc.edu.cn, zhiqiang.wang@mail.ustc.edu.cn, chenghaoran@mail.ustc.edu.cn,

yihangcheng@mail.ustc.edu.cn, duhaohua@buaa.edu.cn, xiangyangli@ustc.edu.cn
† These authors contributed equally to this work.

5
2
0
2
c
e
D
6
1

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
6
1
4
1
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

Abstract

The rapid evolution of Large Language Mod-
els (LLMs) into autonomous agents has led
to the adoption of the Model Context Pro-
tocol (MCP) as a standard for discovering
and invoking external tools. While this archi-
tecture decouples the reasoning engine from
it in-
tool execution to enhance scalability,
third-
troduces a signiﬁcant privacy surface:
party MCP servers, acting as semi-honest in-
termediaries, can observe detailed tool inter-
action logs outside the user’s trusted bound-
In this paper, we ﬁrst identify and for-
ary.
malize a novel privacy threat termed Intent In-
version, where a semi-honest MCP server at-
tempts to reconstruct the user’s private under-
lying intent solely by analyzing legitimate tool
calls. To systematically assess this vulnera-
bility, we propose IntentMiner, a framework
that leverages Hierarchical Information Isola-
tion and Three-Dimensional Semantic Analy-
sis, integrating tool purpose, call statements,
and returned results, to accurately infer user
intent at the step level. Extensive experiments
demonstrate that IntentMiner achieves a high
degree of semantic alignment (over 85%) with
original user queries, signiﬁcantly outperform-
ing baseline approaches. These results high-
light the inherent privacy risks in decoupled
agent architectures, revealing that seemingly
benign tool execution logs can serve as a po-
tent vector for exposing user secrets.

1

Introduction

The rapid advancement of LLMs has catalyzed
their transition from passive text generators to dy-
namic agents capable of solving complex tasks
through external tool usage (Zhao et al., 2023;
Hadi et al., 2023; Chang et al., 2024). To stan-
dardize this interaction, the MCP has emerged as
a critical framework, enabling LLMs to seamlessly
discover and invoke external resources within a
transparent and traceable workﬂow (Anthropic,
PBC, 2025). By decoupling the reasoning engine

from tool execution, MCP allows LLM agents
to broaden their operational scope and access dy-
namic data repositories.

However,

this architectural decoupling intro-
duces signiﬁcant privacy challenges. A typical
MCP ecosystem comprises three distinct compo-
nents:
the User, the LLM Agent, and the MCP
Server. While the User and the LLM Agent
(the central orchestrator) usually operate within a
trusted boundary, the MCP Servers are often man-
aged by third-party service providers. As these
servers execute tool invocation requests outside
the user’s direct control, they are fundamentally
regarded as semi-honest entities. This trust deﬁcit
raises a critical question: Can a semi-honest MCP
server infer sensitive user information solely by
observing legitimate tool interactions?

Existing research on privacy threats for users,
such as model
inversion (Fredrikson et al.,
2015; Morris et al., 2023), membership infer-
ence (Shokri et al., 2017; Carlini et al., 2021), and
attribute inference (Pan et al., 2023), etc, primar-
ily focus on reconstructing sensitive input data or
training data from model outputs or intermediate
features. Yet, the transferability of these attacks
to agent-based systems remains underexplored. In
the context of MCP, we identify an emerging pri-
vacy threat (termed Intent Inversion), where an
adversary operating an MCP server attempts to re-
construct the user’s underlying query intent by an-
alyzing legitimate tool interactions, such as tool
documentation, invocation parameters, and execu-
tion results. For instance, a series of tool calls
requesting dietary recommendations for speciﬁc
medical conditions could inadvertently reveal a
user’s private health status.

To systematically assess this vulnerability, we
propose IntentMiner, a novel framework for in-
tent inversion attacks via step-level tool call anal-
ysis.
IntentMiner operates on the premise that
tool usage patterns contain rich semantic traces of

the user’s original objective. To effectively mine
this intent, we introduce a Hierarchical Informa-
tion Isolation mechanism that segregates tool call
data to prevent information interference. Further-
more, we employ a Three-Dimensional Seman-
tic Analysis approach, which synthesizes insights
from three key perspectives: 1) Tool Purpose Anal-
ysis:
Inferring domain-speciﬁc intent from tool
names and descriptions; 2) Call Statement Analy-
sis: Extracting entity information from speciﬁc in-
vocation parameters; 3) Returned Result Analysis:
Reﬁning and validating intent using the detailed
outputs generated by tool execution.

In summary, our contributions are as follows:
• We formalize the Intent Inversion Attack within
identifying a novel privacy
the MCP scenario,
threat from semi-honest third-party MCP servers.
• We propose IntentMiner, a sophisticated
framework utilizing step-level parsing and multi-
dimensional semantic analysis to accurately recon-
struct user intent from tool invocation logs.
• We provide empirical evidence of this vulnera-
bility on the ToolACE (Liu et al., 2024) dataset,
achieving over 83% intent alignment across multi-
ple LLM reasoners, and propose defensive strate-
gies to strengthen future agentic architectures.

2 Related Works

In this section, we summarize the security and
privacy landscape of LLM agents, categorizing
threats into unauthorized operation, privacy and
asset risks, and performance degradation. We
speciﬁcally highlight the gap in addressing privacy
threats arising from semi-honest third-party inter-
mediaries in the MCP scenario.

2.1 Unauthorized Operations

Attacks in this category aim to manipulate the
agent’s behavior, forcing it to perform actions not
authorized by the user or developer. Prompt In-
jection Attacks embed malicious instructions into
the input stream to override the agent’s original
system prompts or safety constraints (Liu et al.,
In agentic work-
2023; Greshake et al., 2023b).
ﬂows, indirect prompt injection is particularly dan-
gerous, as the agent may ingest malicious content
(e.g., a poisoned webpage) that hijacks its control
ﬂow (Greshake et al., 2023a). Beyond text manip-
ulation, adversaries can exploit the agent’s tool-
use capabilities. Tool Abuse Attacks typically
inject malicious commands into tool parameters

or environment variables, leading the agent to run
harmful code (e.g., rm -rf) or make unauthorized
API calls disguised as legitimate operations (Zhan
et al., 2024; Wang et al., 2025).

2.2 Asset and Privacy Risks

This category encompasses threats that target the
conﬁdentiality of the model (assets) or the sensi-
tive information of the users (privacy). Model Ex-
traction Attacks steal an LLM’s intellectual prop-
erty, such as its architecture and weights, by query-
ing the API and training a surrogate model on the
outputs (Tramèr et al., 2016). Membership Infer-
ence Attacks target the training data, identifying
whether a speciﬁc record was used during the train-
ing phase, thereby violating data assets (Shokri
et al., 2017; Carlini et al., 2021). Most relevant
to our work are Model Inversion Attacks, where
an adversary reconstructs sensitive input features
from the model’s outputs (e.g., conﬁdence scores)
or internal representations (Fredrikson et al., 2015;
Morris et al., 2023). Similarly, Attribute Infer-
ence Attacks attempt to deduce private user at-
tributes (e.g., age, race) from text embeddings or
dialogue history (Pan et al., 2023). However, ex-
isting inversion techniques primarily target the re-
construction of static inputs or training data. They
overlook the risk of inferring dynamic, high-level
user intents from intermediate tool traces (e.g., pa-
rameter logs) in decoupled architectures like MCP.

2.3 Different with Existing Research

Existing studies primarily examine security risks
faced by trusted LLM agents interacting with un-
trusted users (e.g., preventing jailbreak attempts).
Besides, privacy research typically assumes the
model-hosting server is the adversary. However,
the MCP introduces a unique tripartite architecture
involving a User, an Agent, and independent MCP
Servers. The privacy risks posed by these semi-
honest third-party MCP serverswhich observe le-
gitimate tool calls but not the original queryremain
unexplored. Our work bridges this gap by formal-
izing the Intent Inversion Attack, demonstrating
how such intermediaries can infer sensitive user in-
tents from seemingly benign tool invocation logs.

3 Problem Setup

3.1 System Architecture

As illustrated in Figure 1, a typical MCP frame-
work comprises three key components:

boundary, these third-party servers are fundamen-
tally regarded as semi-honest entities.
Figure 1 illustrates the workﬂow between these
components through steps ‹–(cid:176).

3.2 Threat Model

We assume that the attackers are semi-honest MCP
servers. While faithfully executing users’ tool in-
vocation requests, these servers may additionally
infer the users underlying query intents (as shown
in Figure 1), leading to potential privacy breaches.
Consider a scenario where an agent invokes the
Heart_Healthy_Food_Recommender(
function
user_health_condition={blood_pressure:
High,
cholesterol_level:
Borderline
Prediabetes},
High, blood_sugar_level:
dietary_preferences=[fish, vegetables]).
A semi-honest MCP server could infer
that
the user intends to obtain heart-healthy food
recommendations
speciﬁc
health status (high blood pressure, borderline
high cholesterol, prediabetes). This query would
necessarily pass through the MCP server hosting
the relevant medical
tools, potentially expos-
ing sensitive health information to bad actors
operating that server.

tailored to his/her

Attacker Capabilities. We deﬁne the semi-
honest adversary’s capabilities based on their ac-
cess to three key information sources:
1) Tool Documentation: The adversary possesses
the registered tool descriptions and schemas.
2) Invocation Data: The adversary observes the
speciﬁc tool names and input parameters provided
for tool execution.
3) Execution Results: The adversary has access to
the output generated by the tool.

Crucially, these data sources are inherent to the
legitimate MCP workﬂow and require no addi-
tional adversarial actions.

3.3 Attack Formalization

Assuming that a user submits a query Q to LLM
agent A. The agent A parses Q and retrieves n rel-
evant tools based on their documentation Doc(·),
then invokes these tools by sending a request se-
quence ⟨T1(p1), ..., Tn(pn)⟩ to MCP server M,
where p1, ..., pn are parameters extracted from Q.
After execution, M obtains results R1, ..., Rn.
While returning these results to A, the malicious
server M attempts to infer the user’s potential in-
tent I as follows:

Figure 1: The Threat Model in MCP Architecture.

(1) User plays a proactive role by selecting ap-
propriate MCP servers from an open marketplace
tailored to speciﬁc tasks and subsequently issuing
queries to the LLM Agent [›]. The user is consid-
ered a trusted entity, as they possess full authority
over the server selection process and the initiation
of service requests.
(2) LLM Agent serves as the central orchestrator
that interacts with users, interprets user queries, re-
trieves relevant tools from the user-selected reposi-
tory, dispatches invocation requests to correspond-
ing MCP servers [ﬁ], and parses tool execution
results before returning them to the user [(cid:176)]. We
assume the LLM Agent is a trusted entity, as it typi-
cally operates within a secured, local environment
or a veriﬁed cloud infrastructure, strictly adhering
to the user’s instructions.
(3) MCP Servers host speciﬁc utilities, register
their available tools with the LLM Agent [‹], and
are responsible for the actual execution of invoked
tools [ﬂ]. We speciﬁcally focus on MCP servers
utilizing the Server-Sent Events (SSE) transport
mechanism (e.g., Google Map MCP (CabLate,
2025)). These servers are operated by third-party
service providers and function by executing tool
invocation requests (comprising tool names and
parameters) and returning results to the agent.
Given that they operate outside the user’s control

[Query] Please recommend heart-healthy foods for my highblood pressure, borderline high cholesterol, and prediabetes.[Response] - Food_Recommender: ...- Sugar_Controller: ...- Calorie_Guider: ...……[Available Tools' Documents]- Food_Recommender(...)[Tool Retrieve & Call][Tool Execution on the Untrusted MCP Server]{"name": "Food_Recommender", "results":{"food_recommendations": ["Salmon", "Spinach", "Walnuts","Blueberries", "Quinoa", "Legumes"]}}Tool Calls & Paras.Tool DocumentsTool Exec. Results[Intent Inference Attack]- Recommend foods for highblood pressure, cholesterol,and prediabetes.12345UserLLM AgentMCP Server- Based on yourhealth conditions, therecommended heart-healthy food itemsinclude Salmon,Spinach, Walnuts,Blueberries, Quinoa,and Legumes.Figure 2: The System Overview of IntentMiner.

F = arg min

F

G(I, Q),

I =F ({Doc(T1), ..., Doc(Tn)},

⟨T1(p1), ..., Tn(pn)⟩, {R1, ..., Rn}),

where F is an intent inference model and G is an
evaluation metric measuring alignment between
the inferred intent and the original query.

4 Methodology

The system overview of IntentMiner is illustrated
in Figure 2. When a user submits a query Q to a
trusted LLM agent A, the agent selects appropri-
ate tools provided by the MCP server M to fulﬁll
the users request by a series of remote tool calls.
Considering that the MCP server M is untrusted,
IntentMiner is deployed to isolate tool-call infor-
mation (Section 4.2) for semantic analysis across
three dimensions (Section 4.3), and synthesize the
tool-call sequence to infer the users intent I at the
step-level (Section 4.1).

4.1 Step-level Intent Parse

According to the problem formalization in Section
3.3, the LLM agent interprets the user query and
produces a sequence of tool calls to accomplish
the users task. As the MCP server executes these
calls, it naturally forms a step-level structure. Con-
sequently, IntentMiner, operating on a malicious
MCP server, can sequentially analyze the intent as-
sociated with each tool call at the step level:

Ii = Fi(Doc(Ti), Ti(pi), Ri), 1 ≤ i ≤ n

In cases where complex user queries require
multiple tool calls, tool-by-tool analysis applies a
divide-and-conquer strategy to break down reason-
ing into simpler components, which are then inte-
grated to better infer user intent:

I = Fagg(I1, ..., In)

4.2 Hierarchical Information Isolation

the Step-Level Intent Parse described in
First,
Section 4.1 isolates the information associated
with each tool call in IntentMiners input, thereby
preventing interference from mixed information.
Speciﬁcally, we represent the information for each
tool call as a triple (Doc(Ti), Ti(pi), Ri).

Furthermore, the composite information within
Doc(Ti) is decomposed into the tool name, de-
scription, and schema, which will be linked to
Ti(pi) and Ri for subsequent semantic analysis.

Isolated Tool Call Information

Each input instance includes the following
components:
1. Tool Name: Ti
2. Description: Functional summary of Ti
3. Schema:

- Required Field: Deﬁnition of pi
- Properties Field: Deﬁnition of Ri

4. Call Statement: Ti(pi)
5. Returned Result: Ri

4.3 Three-Dimensional Semantic Analysis

For a user query corresponding to a sequence of
tool calls, IntentMiner invokes a reasoner LLM to

User QueryLLM AgentSemanticRepresentationTool RetrieveHierarchicalInformation Isolation Available ToolsIsolated Info.………………Tools.User QueryInferred IntentSameSemanticsTool PurposeAnalysisCall StatementAnalysisReturn ResultAnalysisStep-LevelIntent ParseMCP ServerTrusted AgentUntrusted Remote MCP Serverinfer potential user intent across three semantic di-
mensions, leveraging the hierarchical isolated in-
formation to complete the intent inversion attack.
(1) Tool Purpose Analysis is the most essential
dimension. Potential user intent is often strongly
correlated with tools’ functionality and scope of
application, particularly when only a single tool is
called. Since the tools name and description pro-
vide a general overview of its purpose and use, In-
tentMiner analyzes tool purposes based on these
two sources of information.

Tool Purpose Analysis

(1) Purpose Extraction: Extract potential
purposes from the tool’s name.
(2) Use Case Identiﬁcation: Identify in-
tended use cases from the description.
(3) Domain Determination: Determine
the problem space the tool addresses by
integrating the potential purposes and in-
tended use cases.

(2) Call Statement Analysis supplements the de-
tails that Tool Purpose Analysis cannot capture.
For example, when invoking the Market Trends
API, the location information country="us" is
available only through the parameters in the call
statement. Therefore, IntentMiner aligns these pa-
rameters with the Required Field speciﬁed in the
tool schema to infer entity information in potential
user intents, such as place and person names.

Call Statement Analysis

(1) Parameter Extraction: Extract pi from
the tool call statement Ti(pi).
(2) Schema Alignment: Analyze the rela-
tionship between pi and the Required Field
in Tool Schema.
(3) Intent Reﬁnement: Reﬁne the inferred
user intent of Tool Purpose Analysis.

(3) Returned Result Analysis extracts detailed
information from a complementary aspect. Al-
though the LLM agent parses tool call parame-
ters from the user queryembedding entity infor-
mation that reﬂects the users intentthese parame-
ters may be incomplete. For example, the tool
Get Languages for Country uses BR to refer
to Brazil, which can be ambiguous.
In contrast,
the result provides a complete language name
Portuguese. Therefore, IntentMiner aligns the re-

turned results with the parameters and the Proper-
ties Field in the tool schema to validate and clarify
the intent derived from Call Statement Analysis.

Returned Result Analysis

(1) Parameter Alignment: Analyze the re-
lationship between Ri and pi.
(2) Schema Alignment: Analyze the re-
lationship between Ri and the Properties
Field in Tool Schema.
(3) Intent Validation: Verify whether Ri
supports the intent derived from Call State-
ment Analysis.
(4) Intent Revision: Revise the inferred
user intent using the information within Ri.

Finally, we show the complete process of Intent-
Miner in Algorithm 1, and the prompt details of
IntentMiner can be found in Appendix A.2.

Algorithm 1: IntentMiner

Input

:Documentation Doc(·), Invaction
Data ⟨T1(p1), . . . , Tn(pn)⟩,
Execution Results ⟨R1, . . . , Rn⟩,
Reasoner LLM F

Output : User Intent I.

1 for i ← 1 to n do
2

Itmp
i
Iref
i
i
Ii ← F(Iref
5 return F(I1, ..., In)

3

4

i

← F(Ti, Doc(Ti).desc);
← F(Itmp

, Doc(Ti).reqd, pi);

, Doc(Ti).prop, Ri);

5 Experiments

5.1 Experimental Setup

Datasets. ToolACE is a large-scale dataset for
advancing research on LLM tool retrieval.
It
generates accurate, complex, and diverse tool-
invocation interactions through an automated
multi-agent pipeline. Speciﬁcally, ToolACE em-
ploys a self-evolution synthesis process to build
a comprehensive repository of 26,507 distinct
tools, and simulates realistic interactions among
users, LLM agents, and tool executors (i.e., MCP
servers). The dataset contains 11,300 multi-turn
dialogues, among which 1,043 involve requesting
one or more tool invocations. All evaluations of In-
tentMiner are conducted on the ToolACE dataset.
Evaluation Metrics. We deﬁne three metrics to
evaluate the performance of IntentMiner.

Table 1: Evaluation of Intent Alignment Aintent under Different Reasoner and Evaluator LLMs.

Reas.

Eval.

GPT-5.0

Claude-4.0

DeepSeek-R1

Aintent

GPT-4.1

Claude-3.5

Gemini-2.5

Llama-3.1

DeepSeek-V3

Qwen3

0.8313

0.8581

0.8399

0.8431

0.7622

0.7833

0.7728

0.7728

0.8571

0.8533

0.8552

0.8552

0.8399

0.8178

0.8495

0.8357

0.8255

0.8466

0.8236

0.8319

0.7478

0.7095

0.7383

0.7319

Table 2: Evaluation of Text Embedding Similarity Stext and Entity Match Ratio Mentity under Different Reasoner
LLMs.

Reas. LLM

GPT-4.1

Claude-3.5

Gemini-2.5

Llama-3.1

DeepSeek-V3

Stext

Mentity

0.8139

0.8441

0.7482

0.7805

0.8012

0.7867

0.7754

0.7538

0.8063

0.8101

Qwen3

0.7629

0.8128

1. Intent Alignment Aintent(·): We employ mul-
tiple LLMs G1, ..., Gk as evaluators to determine
whether the inferred intent I aligns with the poten-
tial intent of the original user query Q:

Gi(I, Q) =

{

1,

0,

I aligns with Q

otherwise

Aintent(I, Q) =

1
k

k∑

i=1

Gi(I, Q)

2. Text Embedding Similarity Stext(·): We em-
ploy Microsoft MPNet-Base (Song et al., 2020), a
sentence encoder ﬁne-tuned for semantic similar-
ity, to obtain text embeddings for I and Q. The
semantic similarity between I and Q is then mea-
sured using cosine similarity:

Stext(I, Q) =

M P N et(I) · M P N et(Q)
||M P N et(I)|| · ||M P N et(Q)||

3. Entity Match Ratio Meneity(·): We em-
ploy Google BERT-Large (Devlin et al., 2019)
ﬁne-tuned on the CoNLL-2003 dataset to extract
named entities from I and Q. The metric measures
how well the entities in I align with those in Q:

Meneity(·) =

∑

e∈I

I(e ∈ BERT (Q))
||BERT (Q)||

Comparison Baselines. We utilize six pop-
ular open- and closed-source LLMs as the rea-
soner LLM in Algorithm 1 to evaluate the at-

tack performance of IntentMiner.
These in-
clude: GPT-4.1 (OpenAI, 2024), Claude-3.5 (An-
thropic, 2024), Gemini-2.5 (Google DeepMind,
2025), Llama-3.1 (Meta AI, 2024), DeepSeek-
V3 (DeepSeek-AI, 2024), and Qwen-3 (Bai et al.,
2023). Moreover, as IntentMiner is the ﬁrst to
leverage MCP tool calls for intent inversion at-
tacks, we adopt LLMs conﬁgured with the same
system prompt as IntentMiner as our baselines.

5.2 Main Results

Intent Alignment We select

three LLMs,
GPT-5.0 (OpenAI, 2025), Claude-4.0 (Anthropic,
2025), and DeepSeek-R1 (DeepSeek-AI, 2025), as
evaluators for intent alignment. These evaluators
are distinct from the six reasoner LLMs used in In-
tentMiner. The full evaluator prompt is provided
in Appendix A.3. We assess the intent alignment
of IntentMiners attack results under different rea-
soner LLMs, as summarized in Table 1.

When using the same reasoner LLM, the results
from different evaluators varied by no more than
3.83% in intent alignment. This consistency sug-
gests that the performance of IntentMiners intent
inversion attack produces stable outcomes across
diverse evaluators, rather than being inﬂuenced
by outlier behaviour from an individual evalua-
tor. Furthermore, across different reasoners, In-
tentMiner achieves Aintent exceeding 83% in most
cases, demonstrating its robustness and general-
ization. This indicates that most popular LLMs
can support IntentMiner in accurately inferring an
MCP users intent, underscoring the potential risks
of such intent inversion attacks.

Table 3: Token Cost Comparison:
LLM-Based Baselines.

IntentMiner vs.

Method

IntentMiner

LLM-noCoT

LLM-CoT

Token Cost

1038

1010

1176

reasoner LLMs for comparative experiments. As
IntentMiner represents the ﬁrst intent inversion at-
tack method under the MCP scenario, we estab-
lish baselines by conﬁguring the system prompts
of general LLMs to operate either with or with-
out chains of thought (CoT), as detailed in Appen-
dices A.5 and A.4. The results of our comparative
experiments are summarized in Figures 3 and 4.

First, IntentMiner shows a substantial advan-
tage in inferring user intents that closely align with
the original queries, with an average improvement
of 16.73% in Aintent, validating the effectiveness
of IntentMiner. We attribute the close values of
Stext to the fact that the outputs of IntentMiner,
LLM-noCoT, and LLM-CoT share a similar struc-
tural pattern-typically beginning with phrases such
as "The user intends to ..."-since they employ the
same reasoner LLM. Although some key words
differ semantically, the structural similarity yields
comparable text embeddings. The similar Mentity
scores result from general LLMs ability to readily
identify key entities from tool call statements and
return results, even without information isolation
or multi-dimensional analysis. However, this does
not mean that baseline methods can effectively
compose user intent by these entities. Further-
more, the baseline employing CoT for step-level
analysis performs better than the baseline without
CoT, highlighting the necessity of Step-Level In-
tent Parse in IntentMiner.
Token Costs. Table 3 shows the average to-
ken consumption of IntentMiner and the base-
lines. Although IntentMiner requires additional in-
put tokens for Step-Level Intent Parse and Three-
Dimensional Semantic Analysis, its Hierarchical
Information Isolation mechanism effectively re-
duces redundant tool documentations, resulting in
only a 2.8% increase in token cost compared to
LLM-noCoT. Since LLM-CoT also performs step-
level analysis, IntentMiner even consumes 11.7%
fewer tokens than LLM-CoT.

5.4 Ablation Study

Attack Performance. Consistent with Section
5.3, we also select Gemini-2.5 and GPT-4.1 as

(a) LLM-noCoT Attacker

(b) LLM-CoT Attacker

Figure 3: Attack Performance: IntentMiner vs. LLM-
Based Baselines under Gemini-2.5 Reasoner

(a) LLM-noCoT Attacker

(b) LLM-CoT Attacker

Figure 4: Attack Performance: IntentMiner vs. LLM-
Based Baselines under GPT-4.1 Reasoner

Text Embedding Similarity measures the cosine
similarity between the inferred intent I and the
user query Q. As shown in Table 2, the Stext rang-
ing from 0.7482 to 0.8139 indicate that the intents
inferred by IntentMiner exhibit high semantic con-
sistency and contextual similarity with the original
queries. For instance, the inferred intent "Retrieve
a list of future Azure operational events." closely
aligns with the user query "Could you provide me
with a list of upcoming Azure events? Please start
with the ﬁrst page of results."
Entity Match Ratio measures the proportion of
entities in Q that can be matched in I. As shown in
Table 2, the Mentity ranging from 0.7538 to 0.8441
indicate that IntentMiner effectively infers entities
present in the original queries.
It is worth not-
ing that BERT-Large occasionally splits entities-
such as splitting "VFIAX" into "VFI" and "##X",
or "XtractPro" into "X" and "##tractPro". This
tokenization slightly lowers the measured Mentity
than its true value, which further conﬁrms Intent-
Miner’s accuracy in capturing named entities.

5.3 Comparison Study

Attack Performance. Based on the results pre-
sented in Tables 1 and 2, we select Gemini-2.5,
which achieved the highest Aintent, and GPT-4.1,
which achieved the best Stext and Mentity, as the

IntentMinerLLM-noCoT0.80120.78670.63530.78790.77340.8552IntentMinerLLM-CoT0.71040.80120.80010.78670.79100.85520.84310.69000.84410.84360.81390.8200IntentMinerLLM-noCoTIntentMinerLLM-CoT0.84310.69190.84410.86140.81390.8265Table 4: Ablation Experiments: Token Costs.

Method

IntentMiner w/o Purp. w/o Stmt. w/o Res.

Token Cost

1038

916

891

880

sions where a module and its corresponding iso-
lated information are removed, the complete In-
tentMiner only incurs 13.32%-17.95% additional
token cost. As shown in Figures 5 and 6, the com-
plete IntentMiner improves the accuracy of intent
inversion attacks by 13.97%-21.88%, represent-
ing an acceptable trade-off between attack perfor-
mance and token overhead.

6 Possible Defense

To counter intent inversion attacks introduced by
IntentMiner, we propose three defense strategies,
each tailored to a speciﬁc deployment stage.
• Homomorphic Encryption on MCP Servers:
Homomorphic encryption enables computations
directly on encrypted user parameters and pro-
duces encrypted results. This prevents a semi-
honest MCP server from conducting Call State-
ment Analysis or Returned Result Analysis.
• Anonymization Middleware by Trusted Third
Parties: A trusted third party (e.g., a government
agency) can provide anonymized tool invocation
and result forwarding services. This prevents a
semi-honest MCP server from linking inferred in-
tent to a speciﬁc user.
• Semantic Obfuscation at LLM Agents: The
LLM Agent can send extra requests to confuse at-
tackers. For instance, a query about HIV medica-
tion advice could reveal private health information,
while adding a request to write a popular-science
article on HIV could mislead the attacker into as-
suming the user is a medical professional.

7 Conclusion

In this paper, we formalize the Intent Inversion
Attack within the MCP, demonstrating how semi-
honest third-party servers can reconstruct sensitive
user objectives solely from tool invocation logs.
Our proposed framework, IntentMiner, effectively
exploits these semantic traces to achieve over 85%
alignment with original user queries. These ﬁnd-
ings reveal a signiﬁcant privacy gap in decoupled
agent architectures, proving that metadata leakage
alone is sufﬁcient to compromise user conﬁdential-
ity and necessitating the development of more ro-
bust, privacy-preserving tool-use protocols.

Figure 5: Ablation Experiments: Attack Performance
under Gemini-2.5 Reasoner

Figure 6: Ablation Experiments: Attack Performance
under GPT-4.1 Reasoner

reasoners for ablation experiments. We separately
remove the Tool Purpose Analysis, Call Statement
Analysis, and Returned Result Analysis modules
from IntentMiner, along with their corresponding
isolated information, and compare the attack per-
formance with the complete IntentMiner. The re-
sults are shown in Figures 5 and 6.

First, removing any single module and signif-
icantly degrades the intent inversion performance
(a decrease of 13.97%-21.88% in Aintent), demon-
strating that all three semantic analysis dimen-
sions in IntentMiner are essential. Besides, remov-
ing the Call Statement Analysis module greatly
lowers both Stext (by 7.81%-8.61%) and Mentity
(by 18.06%-19.65%). This decline occurs be-
cause, without user-provided parameters, Intent-
Miner w/o Stmt. produces more ambiguous in-
tents and fails to accurately generate the entities
appearing in user queries. For instance, given the
user query "I want to ﬁnd out which languages are
commonly spoken in Brazil" IntentMiner w/o Stmt.
produces the intent "The user intends to determine
what languages are spoken in a speciﬁc country
using the provided country code, and to check if
Portuguese is an ofﬁcial or common language".
Token Costs. Table 4 presents the average token
consumption of the complete IntentMiner and its
variants, each lacking one of the three modules
described in Section 4.3. Compared with the ver-

Intent Align.Text Embed. Sim.Entity Match R.Intent Align.Text Embed. Sim.Entity Match R.Limitations

References

Limitation of General Reasoner. Our proposed
IntentMiner is built on general LLMs used as
reasoners, which are not speciﬁcally optimized
for intent inversion attacks. Although it already
achieves over 85% accuracy in inferring user in-
tents, we believe that ﬁnetuning a dedicated LLM
reasoning engine for this task could further en-
hance attack performance, thereby more sharply
highlighting the privacy risks users face in decou-
pled toolinvocation frameworks.

Insufﬁcient PrivacySensitive Tools.

Our
experiments with IntentMiner use opensource
datasets commonly used for evaluating tool re-
trieval methods. However, these datasets include
few tool calls involving privacysensitive infor-
mation. For instance, in the ToolACE dataset,
only 204 of 11,300 dialogues contain the key-
word health, and some even refer to environmental
rather than human health. We believe IntentMiner
should be further tested on datasets with more pri-
vacysensitive tools, such as those providing health
or legal advice.

Ethical Considerations

Non-Malicious Use and Defensive Purposes In-
tentMiner proposed in this work is not designed to
acquire or disclose user sensitive information, but
rather to advance user privacy protection. Our ulti-
mate goal is to reveal potential privacy risks within
the MCP framework, thereby motivating practical
defense strategies to enhance its overall security.

Open-Source Data and Models All open-
source datasets and models used in our exper-
iments are obtained from HuggingFace without
modiﬁcation. The commercial LLMs are accessed
through their ofﬁcial APIs. Our use of opensource
resources fully complies with the corresponding
datause agreements and opensource licenses.

Legal and Regulatory Compliance Our re-
search uses legitimate and publicly available data
information.
that contain no sensitive personal
The purpose of this study is to identify privacy
risks in the MCP framework, rather than to dis-
close any personal data. Accordingly, this work
complies with privacy and dataprotection regula-
tions, including GDPR (gdp, 2016), CCPA (ccp,
2018), and the Cybersecurity Law (cyb, 2017).

2016. Regulation (eu) 2016/679 of the european par-
liament and of the council of 27 april 2016 on
the protection of natural persons with regard to the
processing of personal data and on the free move-
ment of such data (general data protection regu-
https://eur-lex.europa.eu/eli/reg/
lation).
2016/679/oj. Ofﬁcial Journal of the European
Union, L119, 1–88.

2017. Cybersecurity law of the people’s republic of
china. http://www.cac.gov.cn/2016-11/07/c_
1119867116.htm. Adopted on November 7, 2016;
effective June 1, 2017.

2018. California consumer privacy act of 2018 (ccpa).
https://leginfo.legislature.ca.gov/faces/
codes_displayText.xhtml?division=3.&part=
4.&lawCode=CIV&title=1.81.5. California Civil
Code, Title 1.81.5, Sections 1798.100–1798.199.

Anthropic. 2024. Claude 3 technical report. https://
assets.anthropic.com/m/61e7d27f8c8f5919/
original/Claude-3-Model-Card.pdf.

2025.

re-
4
Anthropic.
https://www-cdn.anthropic.com/
port.
6be99a52cb68eb70eb9572b4cafad13df32ed995.
pdf.

technical

Claude

Anthropic, PBC. 2025. Model context protocol.

Jinze Bai, Shuai Bai, Yunfei Chu, Zeyu Cui, Kai Dang,
Xiaodong Deng, Yang Fan, Wenbin Ge, Yu Han, Fei
Huang, Binyuan Hui, Luo Ji, Mei Li, Junyang Lin,
Runji Lin, Dayiheng Liu, Gao Liu, Chengqiang Lu,
Keming Lu, and 29 others. 2023. Qwen technical
report. arXiv preprint arXiv:2309.16609.

CabLate. 2025. mcp-google-map: A powerful Model
Context Protocol (MCP) server providing compre-
hensive Google Maps API integration with LLM
https://github.com/
processing capabilities.
cablate/mcp-google-map. Accessed: 2025-12-
14.

Nicholas Carlini, Florian Tramer, Eric Wallace,
Matthew Jagielski, Ariel Herbert-Voss, Katherine
Lee, Adam Roberts, Tom Brown, Dawn Song, Ulfar
Erlingsson, and 1 others. 2021. Extracting training
data from large language models. In 30th USENIX
Security Symposium (USENIX Security 21), pages
2633–2650.

Yupeng Chang, Xu Wang, Jindong Wang, Yuan Wu,
Linyi Yang, Kaijie Zhu, Hao Chen, Xiaoyuan Yi,
Cunxiang Wang, Yidong Wang, and 1 others. 2024.
A survey on evaluation of large language models.
ACM transactions on intelligent systems and technol-
ogy, 15(3):1–45.

DeepSeek-AI. 2024. Deepseek-v3 technical report.

Preprint, arXiv:2412.19437.

DeepSeek-AI. 2025. Deepseek-r1: Incentivizing rea-
soning capability in llms via reinforcement learning.
Preprint, arXiv:2501.12948.

Jacob Devlin, Ming-Wei Chang, Kenton Lee, and
Kristina Toutanova. 2019. Bert: Pre-training of
deep bidirectional transformers for language under-
In Proceedings of the 2019 conference
standing.
of the North American chapter of the association
for computational linguistics: human language tech-
nologies, volume 1 (long and short papers), pages
4171–4186.

Matt Fredrikson, Somesh Jha, and Thomas Ristenpart.
2015. Model inversion attacks that exploit conﬁ-
dence information and basic countermeasures.
In
Proceedings of the 22nd ACM CCS.

Google DeepMind. 2025.

Gemini 2.5 api and
model documentation. https://ai.google.dev/
gemini-api/docs.

Kai Greshake, Sahar Abdelnabi, Shailesh Mishra,
Christoph Endres, Thorsten Holz, and Mario Fritz.
2023a. Not what you’ve signed up for: Compromis-
ing real-world LLM-integrated applications with in-
direct prompt injection. In Proceedings of the 16th
ACM Workshop on Artiﬁcial Intelligence and Secu-
rity, pages 79–90.

Kai Greshake and 1 others. 2023b.

Not what
you’ve signed up for: Compromising real-world llm-
integrated applications with indirect prompt injec-
tion. arXiv preprint arXiv:2302.12173.

Muhammad Usman Hadi, Rizwan Qureshi, Abbas
Shah, Muhammad Irfan, Anas Zafar, Muhammad Bi-
lal Shaikh, Naveed Akhtar, Jia Wu, Seyedali Mir-
jalili, and 1 others. 2023. A survey on large lan-
guage models: Applications, challenges, limitations,
and practical usage. Authorea Preprints.

Weiwen Liu, Xu Huang, Xingshan Zeng, Xinlong Hao,
Shuai Yu, Dexun Li, Shuai Wang, Weinan Gan,
Zhengying Liu, Yuanqing Yu, Zezhong Wang, Yux-
ian Wang, Wu Ning, Yutai Hou, Bin Wang, Chuhan
Wu, Xinzhi Wang, Yong Liu, Yasheng Wang, and 8
others. 2024. Toolace: Winning the points of llm
function calling. Preprint, arXiv:2409.00920.

Yi Liu, Gelei Deng, Yuekang Li, and 1 others. 2023.
Prompt injection attack against llm-integrated appli-
cations. arXiv preprint arXiv:2306.05499.

Meta AI. 2024. Open-source ai models for any applica-
tion: Llama 3. https://www.llama.com/models/
llama-3/#models.

John X Morris and 1 others. 2023. Text embeddings
arXiv preprint

reveal (almost) as much as text.
arXiv:2310.06816.

OpenAI. 2024. Gpt-4.1 model overview. https://
platform.openai.com/docs/models/gpt-4.1.

OpenAI. 2025. Gpt-5 model overview.

https://

platform.openai.com/docs/models/gpt-5.

Xudong Pan and 1 others. 2023.

Privacy risks of

general-purpose language models. In IEEE S&P.

Reza Shokri, Marco Stronati, Congzheng Song, and
Vitaly Shmatikov. 2017. Membership inference at-
In 2017
tacks against machine learning models.
IEEE Symposium on Security and Privacy (SP),
pages 3–18. IEEE.

Kaitao Song, Xu Tan, Tao Qin, Jianfeng Lu, and Tie-
Yan Liu. 2020. Mpnet: Masked and permuted pre-
training for language understanding. Advances in
neural information processing systems, 33:16857–
16867.

Florian Tramèr, Fan Zhang, Ari Juels, Michael K Re-
iter, and Thomas Ristenpart. 2016. Stealing ma-
chine learning models via prediction APIs. In 25th
USENIX Security Symposium (USENIX Security 16),
pages 601–618.

Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan
Liu, Haifeng Sun, Haoran Cheng, Guanquan Shi,
Haohua Du, and Xiangyang Li. 2025. Mcptox: A
benchmark for tool poisoning attack on real-world
mcp servers. Preprint, arXiv:2508.14925.

Qiusi Zhan, Zhixiang Liang, Zifan Ying, and Daniel
Kang. 2024.
Injecagent: Benchmarking indirect
prompt injections in tool-integrated large language
model agents. Preprint, arXiv:2403.02691.

Wayne Xin Zhao, Kun Zhou, Junyi Li, Tianyi Tang, Xi-
aolei Wang, Yupeng Hou, Yingqian Min, Beichen
Zhang, Junjie Zhang, Zican Dong, and 1 others.
2023. A survey of large language models. arXiv
preprint arXiv:2303.18223, 1(2).

A Appendix

A.1 Limitations

A.2 The Prompt of IntentMiner

The Prompt of IntentMiner

You are an intent inference system designed
to analyze user behavior through their tool
usage patterns. Your task is to infer the
user’s underlying intent by examining the
tools they have called, the parameters they
provided, and the results they received.
Your analysis should be thorough and con-
sider:

- The semantic meaning of tool names

and descriptions

- The speciﬁc parameters users provide

when calling tools

- The actual results returned by the tools
- Patterns and relationships between mul-

tiple tool calls

- Context clues from the combination of

all available information
You must provide the most possible user in-
tent, which should be speciﬁc, actionable,
and grounded in the evidence from the tool
calls.
Think step-by-step through the analysis pro-
cess before concluding with your ﬁnal in-
tent predictions.

CONTEXT

Analyze the following tool call information
and infer the user’s intent:
Tool Call Information: ${tools_info}
Above is a list of tool calls made by the user.
Each tool call contains the following infor-
mation:
1. Tool Name: The identiﬁer / name of the
tool
2. Tool Description: A detailed descrip-
tion of the tool’s purpose and application
3. Tool Schema:

- Required Field: Parameters that must

be provided when calling the tool

- Properties Field: Detailed speciﬁcation
of all information returned by the tool, in-
cluding their descriptions and data types
4. Tool Call Statement: The actual call
made by the user with all provided parame-
ters
5. Tool Returned Result: The full result
returned by the tool after execution

OUTPUT

Please follow this thought chain step-by-
step to infer the user’s intent:
Step 1: Tool Purpose Analysis For each
tool in the list, parse and understand:

- What is the speciﬁc purpose of this tool

based on its name?

- What does the tool’s description tell us

about its intended use case?

- What domain or problem space does this

tool address?
Step 2: Call Statement Analysis For each
tool call statement, examine:

- What parameters did the user provide in

their request?

- How do the user’s provided parameters
relate to the ’Required Field’ in the ’Tool
Schema’?

- Based on the tool purpose analysis in
Step 1, what do these speciﬁc parameter
values suggest about the user’s intent?
Step 3: Returned Result Analysis For
each tool’s returned result:

- What information did the tool return

based on the user’s parameters?

- How do the result returned by the tool
relate to the ’Properties Field’ in the ’Tool
Schema’?

- Did the result provide the type of infor-
mation that would support speciﬁc user in-
tents?

- How might the user intent to do use this

returned information?
Step 4:
Intent Inference Based on the
complete analysis above, return the most
possible user intent as a Python list. The
intent should be a clear, speciﬁc statement
about what the user is trying to achieve.
Output Format Requirements:

- Only output the ﬁnal Python list.
- Do not include any explanation, reason-

ing, or text outside of the list.

- The output must strictly follow this for-

mat:
”’
intent = ["Most probable intent"]
”’

A.3 The Prompt of LLM Evaluators

The Prompt of LLM Evaluator

You are an assistant designed to evaluate
intent alignment between an original user
query and an inferred intent.
Your task is to determine whether the user’s
original intent effectively matches the in-
ferred intent.
Follow these steps carefully:
1. Analyze the users original query to un-
derstand user’s core intent
2. Determine if the purpose or desired ac-
tion in the original query is similar with the
inferred intent
3. Ignore minor wording differences, syn-
onyms, or rephrasing - focus on whether the
underlying intent is similar
4. Classify your evaluation using exactly
one of these labels:

- "Correct": The inferred intent accurately
captures the user’s original intent
- "Incorrect": The inferred intent does not
align with the user’s original intent

CONTEXT

User Query: ${user_query}
Inferred Intent: ${inferred_intent}

OUTPUT

You should respond strictly following the
speciﬁed output format:
”’
Result = Correct / Incorrect
”’

A.5 The Prompt of LLM-CoT Inverter

The Prompt of LLM-CoT Inverter

You are an intent inference system designed
to analyze user behavior through their tool
usage patterns. Your task is to infer the
user’s underlying intent by examining the
tools they have called, the parameters they
provided, and the results they received.
You must provide the most possible user in-
tent, which should be speciﬁc, actionable,
and grounded in the evidence from the tool
calls.

CONTEXT

Analyze the following tool call information
and infer the user’s intent:
Available Tools Description: ${tools_desc}
Tool Call Information: ${tools_info}

A.4 The Prompt of LLM-noCoT Inverter

OUTPUT

The Prompt of LLM-noCoT Inverter

You are an intent inference system designed
to analyze user behavior through their tool
usage patterns. Your task is to infer the
user’s underlying intent by examining the
tools they have called, the parameters they
provided, and the results they received.
You must provide the most possible user in-
tent, which should be speciﬁc, actionable,
and grounded in the evidence from the tool
calls.

CONTEXT

Analyze the following tool call information
and infer the user’s intent:
Available Tools Description: ${tools_desc}
Tool Call Information: ${tools_info}

OUTPUT

Output Format Requirements:

- Only output the ﬁnal Python list.
- Do not include any explanation, reason-

ing, or text outside of the list.

- The output must strictly follow this for-

mat:
”’
intent = ["Most probable intent"]
”’

Please follow this thought chain step-by-
step to infer the user’s intent:
Step 1: Tool Description Analysis Ana-
lyze the purpose of the invoked tool based
on the information provided in the Avail-
able Tools Description.
Step 2: Call Statement Analysis Based on
the Tool Call Information, extract and ana-
lyze the parameters supplied during the tool
call.
Step 3: Returned Result Analysis Based
on the Tool Call Information, extract and
analyze the results produced by the tool ex-
ecution.
Step 4:
Intent Inference Based on the
complete analysis above, return the most
possible user intent as a Python list. The
intent should be a clear, speciﬁc statement
about what the user is trying to achieve.
Output Format Requirements:

- Only output the ﬁnal Python list.
- Do not include any explanation, reason-

ing, or text outside of the list.

- The output must strictly follow this for-

mat:
”’
intent = ["Most probable intent"]
”’

