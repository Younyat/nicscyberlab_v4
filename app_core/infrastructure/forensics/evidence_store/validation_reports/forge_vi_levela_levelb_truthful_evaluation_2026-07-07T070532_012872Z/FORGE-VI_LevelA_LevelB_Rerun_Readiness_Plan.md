# FORGE-VI Level A / Level B Rerun Readiness Plan

Current decision: **Decision D: a fresh Level B campaign is required before final Level B paper claims.**

Reasons:
- Level B accepted denominator is only n=0
- OT/industrial export is not preserved in the current Level B artifacts
- packet-level Modbus confirmation and defensible Wazuh trigger mapping are not preserved/computed strongly enough for final claims

## A) What is required for a final Level A campaign
A fresh standalone Level A campaign is optional and only needed if a separate final Level A stability denominator is required.
Minimum acceptance criteria:
- N_A = 6 accepted analysis repetitions
- same sealed input case
- same input manifest hash
- same analysis pipeline version
- same reconstruction criteria
- same relation definitions
- same weights
- all output metrics recorded
- all differences between repetitions explicitly reported

## B) What is required for a final Level B campaign
Fresh homogeneous Level B campaign required if final Level B claims are needed.
Minimum acceptance criteria:
- N_B = 6 accepted incident-to-case repetitions
- same deployment
- same scenario_id
- same attack_profile_id and version
- same acquisition_profile_id and version
- same procedure_version
- same analysis_pipeline_version
- all case_ids recorded
- all exclusions recorded
- network, host, memory, disk, alert and OT/industrial preservation reported honestly
- pipeline timings available
- manifest/custody verification mode explicit
- causal reconstruction generated per case
- nested Level A analysis over each Level B case recorded

## C) What can be resolved with reporting only
Can be resolved with reporting only:
- clearer denominator labeling
- declared vs observed wording
- explicit preliminary-only labeling
- optional reporting-only Modbus packet parser over preserved PCAPs only in campaigns where preserved PCAP evidence actually exists

## D) What requires reanalysis over existing artifacts
Requires reanalysis over existing artifacts only:
- packet-level Modbus confirmation from preserved PCAPs only when preserved PCAP evidence actually exists; this does not apply to the current accepted Level B case because preserved_segments=0 and pcap_artifact_count=0
- stronger provenance joins across already preserved alert and network artifacts

## E) What requires changing preservation/acquisition/analysis
Requires changing preservation/acquisition/analysis before a new final campaign:
- OT/industrial export preservation
- explicit persistence of deployment_id, attack_profile_version, procedure_version, analysis_pipeline_version, and git_commit
- explicit Wazuh trigger-to-case binding if final trigger mapping is needed
- integrity reporting that separates hash mismatch from missing artifact counts

## F) What obligates a fresh campaign
Obligates a fresh campaign rather than reusing current n=0 accepted Level B case(s):
- any acquisition or preservation change that affects what evidence is captured
- any analysis or reconstruction change that affects generated metrics or relation states
- any metadata persistence change needed for final comparability
- any final Level B denominator increase from n=0 to N_B=6
Current accepted Level B cases must remain preliminary audit only and must not be pooled with new post-change campaigns.

Current denominators:
- `N_A_total = 13` standalone Level A executions
- `N_B_accepted = 0` accepted Level B cases
- `Industrial / OT evidence preserved = False`