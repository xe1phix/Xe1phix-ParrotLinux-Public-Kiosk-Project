# BOOK-1: Intro to overview of awareness (Plan & Build)
Security Awareness Maturity Model:
Non-existent -> Compliance-focused -> Promoting awareness and behavior change -> Long-term Sustainment and culture change -> Metrics framework

Level-1: Non-existent: Employees have no idea that they are the target | They do not know or understand organization security policies | Easily fall victim to cyber or human-based attacks

Level-2: Compliance focused: To meet specific compliance or audit requirements | Training is limited to annual or ad-hoc basis | Employees are unsure or org policies, their role in protecting org info assets, and how to prevent, identity or report security incidents

Level-3: Promoting awareness and behavior change: Identify training topics with greatest impact | Continual reinforcement throughout the year | Content is communicated in engaging and positive manner | Behavior change at work, at home, at travel | Employees are aware of org policies, actively recognize, prevent and report incidents

Level-4: Long-term sustainment and culture change: Program has processes and resources in place for long term life cycle | Annual review of training content and communication methods | Program is part of org culture | changed people’s beliefs, values, perceptions on security

Level-5: Metrics framework: Track progress and measure impact | Continuous improve and show ROI
-	Metrics are part of every stage. 5th stage is truly reinforcing it by demonstrating via metrics

Maturity model roadmap: Directions on how to reach higher levels
Maturity model indicator matrix: Identifies current stage we are in based on numerous indicators

NIST SP 800 series -> security policies, standards, and best practices, etc.
SP800-50: Security Awareness (Different stages of learning for an individual)
-	Education: Goes beyond training! Theory, Body of Knowledge, WHY part!
-	Training: Teach new skills | Tends to be role specific | e.g. give command line tools to find an indication that system is compromised
-	Awareness: Focusses on changing behaviors e.g. what to look in an email and decide not to click a link

Need to create a new role as Secure Awareness & Communications manager (someone who likes people and can detects behavior change)

# BOOK-1: Level-2: Compliance focused (Plan & Build)
Security Awareness Compliance Requirements:
-	ISO/IEC 27001 and 27002
-	20 CIS CC
-	NIST CSF
-	PCI DSS
-	GDPR

Enforcing awareness via compliance will provide less budgets/resources from management. Instead focus on being secure, which inherently covers compliancy.

Awareness training policy: page-15 of workbook (be careful about SHOULD vs MUST)
“MUST” policies must be audited
-	Enforcement: higher enforcements rules improve compliancy % in the organization
o	Primary enforcement (stronger) and secondary enforcement (weaker) 
-	Handling resistance: Define process of action for these people
 
# BOOK-1: Level-3: Promoting awareness and behavior change (Plan & Build)
Risk = vulnerabilities x threat x impact
-	Human risk is managed by changing human behavior

Vulnerabilities = Technical | Processes | Human
-	Process vulnerabilities: weakness related to process, policies, procedures, standards, awareness
-	Human vulnerabilities: Psychological ones | Overestimate risk for highly visual events & those not in control | often underestimated

Threats = Environmental (acts of god | floods | fire | earthquakes | tornados, etc.) | Accidental (Mistakes by employees, vendors, contractors, Accidental data log may be bigger than we think) | Deliberate (targeted | Opportunistic) | ISO27005 classification
-	In the past targeted & opportunistic were different. Now they are blending (motivation & TTPs)

Social engineering: most common method | targeted and opportunistic threats are same against humans, Motivation varies though

Impact: damage or harm event causes to our org | awareness can reduce impact e.g. data backups, using encryption | develop & train humans to identify and report incidents
-	Human risk is mitigated by changing human behaviors

Steps:
1.	Start with leadership support
2.	Quantify the problem – sense of urgency (incidents, Assessments, Statistics)
3.	Model the solution (maturity model, with costs)

Always start with a program / project charter. (page-18 of lab book)
-	Goals: are strategic | Objectives: are results to achieve the goals
o	E.g. of goal: help reduce human risk

Advisory board to assist on maintaining the program.
-	Advisory board matrix (who, department, reason for being on board)

Fogg Behavior model: B = MAP [Behavior = Motivation x Ability x Prompt]
-	The simpler the content, the higher the chance for people to participate
After the advisory board, we need to plan: WHO (are we targeting behavior to change) | WHAT (to teach? Risks to manage?) | HOW (to engage and communicate?)

# BOOK-1: WHO (Plan & Build)
Right training to right people | No more | Drives the WHAT and HOW
Strategy: Foundation (baseline) | Risk based | Region based | Policy based

Key issues to keep in mind: content should be non-technical | cannot assume they understand commonly used security terms

WHO? Employees | Contractors/Vendors | IT staff / developers / Network engineers (technical people don’t mean security aware people, same baseline as employees but additional) | Senior leadership (+executive assistants)
-	For senior executives: often short training | focus on key threats | explain value of security awareness | White Glove Program: in person training to executive by security experts
First learn about your target well | Identify privileged users / define unique reqs for them
Who to train first? Start with one and build on success | Identify first one by risk, sr leadership, quick win
You don’t want to identify different groups and different trainings and do all together at same time

# BOOK-1: WHAT (Plan & Build)
To be successful, keep content short and modular. | What risks are unique to group that to be covered | 
Think of what not to teach | Core modules + additional blocks per profile (Dev, Leadership, IT, HR, etc.)

Two categories of topics need to be covered: REQUIRED (Policy, Compliance, Legal, etc.) | RISK (by business)
-	Start from ERA (Enterprise Risk Assessment) – Human risks identified
-	Simplified Human ERA:- (e.g. NIST SP 800-30)
Look at VDRIR | Discuss with Threat Intel team (TTPs). Else check attack.mitre.org | also check popular twitter accounts for upcoming threats/human risks e.g. Bruce Schneier, kerbsonsecurity, etc.

Apply Cyber Kill Chain: recon -> weaponization -> delivery -> exploitation -> installation -> c2 -> actions on objectives

Prioritize human risks: Quantitative (precise, accurate, time consuming) and Qualitative (neither accurate, nor precise but good-enough approach)
-	Qualitative approach: Risk matrix -> probability vs. impact | probability depends on threats & vuln | Page-22 of lab workbook (definitions of very low, low, medium, high, very high)

Need to create learning objectives for each identified and prioritized top risk | Learning objectives document contain: Title, Target, Goal, Background, Learning objectives
-	A learning objective must not mention the goal as ‘understand’ or ‘learn’. Instead it must say learner can ‘explain’, ‘identify’ or ‘demonstrate’.
https://www.cmu.edu/teaching/designteach/design/learningobjectives.html 

Bloom’s Taxonomy: verbs in learning objectives (level 1,2,3) https://www.cmu.edu/teaching/designteach/design/bloomsTaxonomy.html 
-	Don’t use the words: “know” or “understand” | Instead target groups must “demonstrate” or “identify” or “explain”
Password security guidelines.

# BOOK-2: HOW (Implement & Maintain)
Most programs fail horribly in this area | Motivating change: create sense of urgency | awareness of need for change | start with why
AIDA marketing model: simple, flexible, good for security initiatives
-	Marketing funnel: Attention | Interest | Desire | Action (conversion or call to action)

Attention: start with problem (do not assume they know it)
Interest: start showing the solution (tools)
Desire: Change people’s mindset from ‘I like it’ to ‘I want it’
Action: Create a sense of urgency

WIIFM: What’s In It For Me?
 
Now that the AIDA information is available, how do we communicate this? Need to know the Organization culture.
-	Conservative vs. Outgoing
o	Outgoing are fun, open to new ideas, use latest technology, expressive in communication
o	Conservative are process/policy driven, work directly with people, read than watch

Different cultures have different acceptable levels (sensitivity): e.g. Politics, Religion, Humor
One reason for awareness training is boring is that creator ensures training don’t offend anyone.
-	The more generic the training is, the less likely someone will be offended
Have a structured way to get feedback (both good and bad) from the training participants.
-	Leadership must know that these processes exist.

Generational differences must be also be considered when creating awareness training material.
-	Page 35 in lab workbook (traditionalist, baby bloomer, Gen X, Gen Y/Millennials, Gen Z)

Localization: language (dialects/accents), regions, time zone, etc.
Neutral Imagery: Do not use pictures of real people | use hand-drawn, computer-generated, canton cut-outs, stop motion, etc. | Cannot determine race, religion, nationality | Can be modified in future
https://www.istockphoto.com/
-	Check licensing issues (especially free sites)

Branding: 	Mascot		|	Logo	|	Tagline
-	Character that communicates awareness program
-	Image that brands your team or program
-	Name of your program

New hire onboarding process

Communication strategies: Primary and Reinforcement
-	Primary: all topics at once, often mandatory, mostly compliance driven
-	Reinforcement: no new topics taught, rarely mandatory, reinforces topics taught in primary
o	Always include contact info (Fogg Behavior Model)
o	Newsletters are a way to reinforce topics (inexpensive) | Can go viral

Methods of training: Primary (ILT, Instructor-Led AND CBT, Computer-Based)
-	ILT: effective way to reach audience, interactive, low initial costs, easy to update
o	Disadvantages: Low attendance, if not mandatory | doesn’t scale for large org | handling multilingual environments is not easy
-	CBT: eLearning, online training, mobile training (mtraining) | take on own schedule/pace, track, reach large audience, flexible
o	Disadvantages: less interaction, 6 to 12 months to create effective videos, cost to develop and maintain training material

3 key tips to effective presentation: start at the beginning, body language, questions
-	Intro urself, start with problem
-	Never read slides, make sure nothing is between you and your audience
-	Repeat the question, when not interactive instructor should ask questions, careful w/ sharpshooter

Webcast tips: test ahead of time the software for online training | kill other apps running | ask lot of Qs throughout the talk

Interactive vs. Static videos: Static videos are good for compliance | Interactive videos are “sticky” and more time consuming | combination of both is better

Licensing from a vendor? Who’z hosting the content? Frequency of update? Customization? Assessments and reporting? Cost to license?

Creating our own: Adobe Captivate | Articulate Storyline | Lynda.com for training & YouTube for ideas
-	Don’t forget the music (it adds fun)
Deliver/Track training: ADA/Fed 508 compliant (e.g. sub-titles for hearing impair), mobile device support, translation, auto email communication, quizzes, certificates, reporting, etc.

LMS (Learning Management System): repository for training course
-	SCORM: Shareable Content Object Reference Model (both training & LMS must be compliant)

Newsletters: (As a reinforcement): Create with word, canva, Adobe InDesign.
-	Millennial version of newsletter -> short and punchy | visual | more graphical
-	Promotional items

Internal Social Media: 
-	Another way to reach out to various employees on awareness topics | Yammer | YamJams

Internet Memes & Special Events (hacking demos, escape rooms, OSINT assessment)
October – Cybersecurity awareness month!

Bring in guest speakers! 

Gamifications: codeacademy, khanacademy, etc. | Jedi Levels: Appentice, Padawan, Knight, Master, Grand Master | Guide our leaders (3 key behaviors they can tell employees when they meet them) | Positive Peer Pressure (e.g. clean desk policy) | 

# BOOK-2: Long-term Sustainment and Culture change
Takes 3 to 10 years to achieve (on average) | Starts with behavior change and culture change follows eventually | 

Executive support: both for creating awareness and also to maintain it | senior executive on advisory board | Get quick wins (feedback surveys)

Keep updating the training content at least once a year | Keep updating the ‘how-to-communicate’ | 

Use of ‘Security Ambassadors’ to deploy the program globally (Champions, Advocates, Sentinels)
-	Benefits of such network is: Scalability | Control | Engagement | Information

Align human resources for good behaviors from employees (e.g., impact on compensation, etc.)
-	No behavior changes? ASK WHY! Check motivation (they don’t want to exhibit), Ability (pretty hard/frustrating task), Prompt (they don’t know to do it)

# BOOK-2: Metrics Framework
Measuring human behavior | Are we reducing risk? | http://www.securitymetrics.org/ | Focus on few metrics | set a baseline (first calculated metric) | 

Two types of metrics: Compliance metrics (just completed ones) | Impact metrics (are we changing behavior?) | Strategic metrics
-	Majority of people fall victim to phishing in the first 15 min or hour of campaign launch
o	Phishing assessments are low cost, simple, quantifiable, actionable.

Difference between technical metrics and human metrics: “Humans have feelings”
-	Do not embarrass people | do not release names of those who fail | focus on real world risks, do not trick people | at least two ways to detect a phish

Get approval & coordinate before assessments | else launch pilot to blockers (HR / legal, etc.)
-	Start with Basic email | Then go to Targeted email
Click results -> Give feedback (has better learning experience but not great metrics as people share the news of ongoing phish test with their colleagues) or No Feedback
-	Give feedback 24 hours later, if decided to share feedback
-	Include monthly security newsletter

Handling violations (repeated clickers): 
-	1st violation: Notify employee or follow-up training
-	2nd violation: employee is notified and manager is copied
-	3rd violation: manager is required to have meeting with employee and report results to security
-	4th violation: employee reported to HR

Legal aspect of using another brand name / company name in phishing emails campaign: Unclear.
-	Not recommended though

Human sensors: How many of the employees reported a phishing attack is in place.

In some cases, metrics data may already exist | e.g. SOC team, Help Desk, HR, etc.

Strategic metrics: CISO cares about | nbr of policy violations, etc. Ask your management on what kind of metrics makes sense to them.

Collecting metrics is only job half done | Presenting metrics to leadership (Verizon DBIR is an example of how to present metrics). | Create department specific metrics

Rewarding: Recognition | encourage positive behavior | Challenge coins
--- END ---
