ML INTEGRATION
===============
The live File Activity monitor now includes an unsupervised Isolation Forest anomaly detector over the eight behavioural features.

Important: this is anomaly detection, not a validated malware classifier. The model learns a baseline from low-risk activity windows and flags unusual activity. Confirmed malware remains a separate scan classification until a properly labelled file-activity dataset is supplied.

First run: the monitor collects 12 low-risk windows, trains and saves activity_behavior_model.pkl, then scores subsequent windows.

The existing malware_model.pkl is trained on the MalMem2022 memory-forensics feature schema (55 features) and therefore must NOT be applied directly to the 8 file-activity features.
