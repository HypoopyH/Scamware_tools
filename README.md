# Scamware Analyzer

Feature：

1. Check Native/hybrid/web development paradigm 
2. App Generator identification, decryption, and configuration information parsing
3. Separate the user-code from the boilerplate code of web apps.
4. Retrieve remote resource (HTML,CSS,JS) of hybrid apps.

Check the supported module list [here](https://anonymous.4open.science/r/Scamware_tools-B576/ResExtractor/libs/modules/README.md). 

## Introduction

This paper takes the first step towards systematically studying Sacmware and their ecosystem by investigating 1, 119 real-world scam apps collected from December 1, 2020 to January 1, 2022. 

We propose to build a novel framework, **ResExtractor**, for automatic analysis of Scamware. The design of **ResExtractor** is based on three key insights.

> First of all, the hybrid development paradigm occupies an absolute proportion at Scamware.

> Second, app generator services are abused in Scamware.

> Third, Scamware has anti-anlysis technologies, such as virtual machine environment detection, encryption, etc.

Based upon these insights, we deliberately designed a series of analysis for hybrid apps, and the specific details will be mentioned in their corresponding folders.

## Requirements

See in `ScamwareAnalyzer/ResExtractor/requirements.txt` .

## Repository Contents

- The source code of  ResExtractor locates in `ScamwareAnalyzer/ResExtractor/` directory. 
- It includes functions such as App Generator identification, decryption, and configuration information parsing.
- In addition, it provides functions such as monitoring remote servers, analyzing remote resources (inlcuding HTML,CSS,JS),  automatically taking screenshots, and etc.
- All details is located in `ScamwareAnalyzer/ResExtractor/README.md`

