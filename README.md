# Scamware Analyzer

Feature：

1. Check Native/hybrid/web framework
2. Check the developer information and permission in Mainfest
3. Separate the low-code from boilerplate code of web apps.
4. Retrieve remote resource of web apps.

Check the supported module list [here](https://anonymous.4open.science/r/Scamware_tools-B576/ResExtractor/libs/modules/README.md). 

## Introduction

This paper takes the first step towards systematically studying Sacmware and their ecosystem by investigating 1, 119 real-world scam apps collected from December 1, 2020 to January 1, 2022. 

We propose to build two novel frameworks, ResExtractor and ResCheck, that perform automatically analyzing towards Scamware. The design of ResExtractor and ResCheck is based on three key insights. 

> First, hybrid development paradigm is abused in Scamware. 

> Second, app generator services are abused in Scamware.

> Third, Scamware will detect whether the environment in which they are running is a virtual machine.

Based upon these insights, we deliberately designed a series of analysis functions for webapp, and the specific details will be mentioned in their corresponding folders.

## Requirements

See in `ScamwareAnalyzer/ResExtractor/`  directory.

## Repository Contents

- The expand web app ResExtractor is in `ScamwareAnalyzer/ResExtractor/` directory. 
- It contains App Generator recognition, decryption and analysis capabilitiesIcon.
- In addition, it provides analysis capabilities such as monitoring remote servers, analyzing remote resources, comparing webpage similarity, and automating screenshots.
- All details is located in `ScamwareAnalyzer/ResExtractor/README.md`

