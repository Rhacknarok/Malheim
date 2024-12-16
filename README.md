<p align="center"><img src="https://socialify.git.ci/rhacknarok/malheim/image?description=1&amp;descriptionEditable=Recover%20malware%20directly%20from%20your%20honeypots&amp;language=1&amp;name=1&amp;owner=1&amp;pattern=Transparent&amp;stargazers=1&amp;theme=Auto" alt="project-image"></p>

<div align="center">
<a target="_blank" href="https://discord.gg/y2dp5guGpf" rel="noopener noreferrer" title="Join Rhacknarok's Discord">
<img alt="Join Rhacknarok's Discord" src="https://raw.githubusercontent.com/Rhacknarok/readme-assets/136a87ac8e917fa1d872779cbc6e98301b4a5814/discord.png" width="150" />
</a>
</div>
<hr />
<h2>🧐 Why we made this?</h2>
<div align="justify">
<p>We, the members of Rhacknarok, are passionate about cybersecurity and have a single goal: to learn. We've launched a new project called Long Live the Malware.
The aim is to set up a honeypot and collect as many malware samples as possible for analysis.</p>
<p>Ideally, we'd like to recover samples that are not yet detected by the various security solutions. So here's a message for those who attack us: please, make an effort! 🙏</p>
<p>The Malheim project has been developed to recover these samples and put them online on a GitHub repo, to keep track of them. At the same time, it will upload the hashes and/or files to Virustotal to find out whether they have been spotted or not.
Malheim's code may not be optimal: we're not very good at development. All suggestions are welcome. 😉🐍</p>
</div>
<h2>🚀 Features</h2>
Here're some of the project's features:

*   Recovering malware samples ;
*   Upload hashes and files to Virustotal ;
*   Save samples on your Github repo.

<h2>🛠️ Installation Steps:</h2>

<p>1. Clone this repository</p>

```
git clone https://github.com/Rhacknarok/malheim.git
```

<br />
<p>2. Install dependencies</p>

```
cd malheim
python3 -m pip install -r requirements.txt
```

<br />
<p>3. Configure .ini file</p>

> Edit **config.ini** file.

<br />
<p>4. Execute Malheim</p>

```
python3 malheim.py
```

<br />
<p>5. Crontab [OPTIONAL]</p>
Add malheim.py to your crontab to run it periodically.

<h2>💻 Built with</h2>

Technologies used in the project:

*   Python ;
*   Thor's hammer ;
*   Love ❤️

<h2>👀 What next?</h2>
<div align="justify">
<p>We're continuing to work on this project, improving it as much as we can. If you like the project and would like to take part, we'd be delighted to receive your contributions. 😁✌️</p>
</div>

<h2>📞 Contact</h2>

[![Discord](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/y2dp5guGpf)  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/rhacknarok)  
