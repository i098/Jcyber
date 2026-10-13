# HexStrike on Kali — the registry is Kali's package list, near-100% coverage.
# Needs the hexstrike_server.py + requirements.txt next to it (upstream repo).
# Build:  docker build -f deploy/hexstrike.Dockerfile -t hexstrike:full <hexstrike-repo>
# Run:    docker run -d --name hexstrike -p 8899:8888 hexstrike:full
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/exploitdb:/usr/local/bin:$PATH

ARG PKGS="curl wget git ca-certificates build-essential python3 python3-pip \
    default-jdk ruby-full cargo \
    nmap masscan rustscan gobuster dirb nikto sqlmap hydra john hashcat \
    wfuzz ffuf feroxbuster nuclei amass subfinder dalfox wafw00f arjun \
    dirsearch theharvester sherlock recon-ng dnsenum fierce dnsutils whois \
    exiftool binwalk radare2 checksec foremost testdisk sleuthkit \
    steghide hashpump outguess zsteg \
    nbtscan arp-scan netcat-openbsd tcpdump tshark samba smbclient smbmap \
    enum4linux enum4linux-ng netexec responder evil-winrm \
    metasploit-framework exploitdb one-gadget ropper gdb pwntools \
    dotdotpwn xsser httpie sslscan \
    pacu seclists wafw00f"

RUN apt-get update && apt-get install -y $PKGS || \
    (for p in $PKGS; do apt-get install -y "$p" >/dev/null 2>&1 || echo "skip: $p"; done) \
    && rm -rf /var/lib/apt/lists/*

# Go tools Kali doesn't package
RUN go install github.com/lc/gau/v2/cmd/gau@latest \
  && go install github.com/daeuniverse/waybackurls@latest \
  && go install github.com/projectdiscovery/katana/cmd/katana@latest \
  && go install github.com/lc/qsreplace@latest \
  && go install github.com/tomnomnom/anew@latest \
  && go install github.com/hahwul/dalfox/v2@latest \
  || echo "some go tools skipped"

# pip layer: server deps + registry tools Kali doesn't package
RUN pip install --break-system-packages --no-cache-dir \
      flask requests psutil aiohttp beautifulsoup4 mitmproxy \
      arjun paramspider dirsearch sherlock shodan censys uro \
      prowler kube-hunter checkov scout-suite volatility3 \
  || echo "some pip tools skipped"

# Script/source tools
RUN git clone -q --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
      && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit || true \
    && git clone -q --depth 1 https://github.com/faith0x7/libc-database.git /opt/libc-database || true \
    && git clone -q --depth 1 https://github.com/pwndbg/pwndbg.git /opt/pwndbg || true \
    && git clone -q --depth 1 https://github.com/OWASP/DotDotPwn.git /opt/dotdotpwn \
      && ln -sf /opt/dotdotpwn/DotDotPwn.pl /usr/local/bin/dotdotpwn || true \
    && cargo install --locked x8 || cargo install x8 || echo "x8 skipped"

WORKDIR /opt/hexstrike
COPY requirements.txt hexstrike_server.py ./
RUN pip install --break-system-packages --no-cache-dir \
      flask requests psutil aiohttp beautifulsoup4 selenium mitmproxy \
 && (pip install --break-system-packages --no-cache-dir -r requirements.txt || \
     echo "some optional requirements skipped")

EXPOSE 8888
CMD ["python3", "hexstrike_server.py"]
