import random

# DFIR 면접 질문 뱅크
DFIR_QUESTIONS = {
    "기초": [
        {
            "q": "디지털 포렌식의 4대 원칙은 무엇인가요?",
            "a": "정당성, 재현성, 신속성, 연계보관성(Chain of Custody)입니다."
        },
        {
            "q": "휘발성 데이터 수집 순서(Order of Volatility)를 설명해주세요.",
            "a": "레지스터/캐시 → 메모리 → 네트워크 상태 → 프로세스 → 디스크 → 원격 로그 순으로 휘발성이 높은 것부터 수집합니다."
        },
        {
            "q": "침해사고 대응 절차(Incident Response)의 단계를 설명해주세요.",
            "a": "준비(Preparation) → 탐지/분석(Detection/Analysis) → 억제(Containment) → 제거(Eradication) → 복구(Recovery) → 교훈(Lessons Learned)"
        },
        {
            "q": "이미징(Imaging)과 복제(Cloning)의 차이점은?",
            "a": "이미징은 비트 단위 복사본을 파일로 생성, 복제는 동일한 물리적 디스크를 만듭니다. 포렌식에서는 주로 이미징을 사용합니다."
        },
        {
            "q": "해시(Hash)를 포렌식에서 사용하는 이유는?",
            "a": "무결성 검증을 위해 사용합니다. 원본과 사본의 해시값이 일치하면 데이터가 변조되지 않았음을 증명할 수 있습니다."
        },
    ],
    "윈도우": [
        {
            "q": "Windows 레지스트리 하이브(Hive) 5가지를 말해주세요.",
            "a": "SAM, SECURITY, SYSTEM, SOFTWARE, NTUSER.DAT (DEFAULT도 포함하면 6개)"
        },
        {
            "q": "Prefetch 파일의 역할과 포렌식적 가치는?",
            "a": "프로그램 실행 속도 향상을 위한 캐시 파일입니다. 실행된 프로그램명, 실행 횟수, 마지막 실행 시간, 참조 파일 목록을 알 수 있습니다."
        },
        {
            "q": "$MFT가 무엇이고 어떤 정보를 담고 있나요?",
            "a": "Master File Table로 NTFS의 모든 파일/폴더 메타데이터를 담고 있습니다. 파일명, 생성/수정/접근 시간, 크기, 위치 정보 등을 포함합니다."
        },
        {
            "q": "NTFS의 $UsnJrnl은 무엇인가요?",
            "a": "파일 시스템 변경 저널입니다. 파일 생성, 삭제, 수정, 이름 변경 등의 기록이 남아 타임라인 분석에 유용합니다."
        },
        {
            "q": "ShimCache와 AmCache의 차이점은?",
            "a": "둘 다 프로그램 실행 흔적을 남깁니다. ShimCache는 SYSTEM 하이브에, AmCache는 별도 파일(Amcache.hve)에 저장됩니다. AmCache가 더 상세한 정보를 담고 있습니다."
        },
        {
            "q": "Windows 이벤트 로그에서 로그온 성공/실패 이벤트 ID는?",
            "a": "성공: 4624, 실패: 4625입니다. Security.evtx에서 확인할 수 있습니다."
        },
    ],
    "메모리": [
        {
            "q": "메모리 포렌식에서 확인할 수 있는 주요 정보는?",
            "a": "실행 중인 프로세스, 네트워크 연결, 로드된 DLL, 레지스트리 키, 암호화 키, 악성코드 등을 확인할 수 있습니다."
        },
        {
            "q": "Volatility에서 프로세스 목록을 확인하는 명령어는?",
            "a": "windows.pslist, windows.psscan, windows.pstree 등이 있습니다. psscan은 숨겨진 프로세스도 탐지할 수 있습니다."
        },
        {
            "q": "프로세스 인젝션(Process Injection)을 탐지하는 방법은?",
            "a": "malfind 플러그인으로 의심스러운 메모리 영역을 찾고, VAD(Virtual Address Descriptor) 분석으로 비정상적인 메모리 권한을 확인합니다."
        },
        {
            "q": "메모리 덤프 도구 3가지를 말해주세요.",
            "a": "DumpIt, WinPmem, FTK Imager, Belkasoft RAM Capturer 등이 있습니다."
        },
    ],
    "네트워크": [
        {
            "q": "C2(Command & Control) 통신을 탐지하는 방법은?",
            "a": "비콘 패턴(주기적 통신), 비정상 포트 사용, DNS 터널링, 암호화된 트래픽 패턴, 알려진 IOC 매칭 등으로 탐지합니다."
        },
        {
            "q": "DNS 로그에서 확인해야 할 악성 지표는?",
            "a": "DGA(Domain Generation Algorithm) 패턴, 긴 서브도메인(터널링), 높은 쿼리 빈도, TXT 레코드 악용, 의심스러운 TLD 등입니다."
        },
        {
            "q": "Lateral Movement의 주요 기법 3가지는?",
            "a": "PsExec, WMI, WinRM, RDP, SMB, Pass-the-Hash, Pass-the-Ticket 등이 있습니다."
        },
    ],
    "악성코드": [
        {
            "q": "정적 분석과 동적 분석의 차이점은?",
            "a": "정적 분석은 실행 없이 코드/구조를 분석하고, 동적 분석은 실제 실행하며 행위를 관찰합니다."
        },
        {
            "q": "파일리스(Fileless) 악성코드의 특징과 탐지 방법은?",
            "a": "디스크에 파일을 남기지 않고 메모리에서만 실행됩니다. PowerShell 로그, WMI 이벤트, 메모리 분석으로 탐지합니다."
        },
        {
            "q": "PE 파일 구조에서 IAT(Import Address Table)의 역할은?",
            "a": "외부 DLL에서 가져오는 함수들의 주소를 저장합니다. 악성코드 분석 시 어떤 API를 사용하는지 파악하는 데 중요합니다."
        },
    ],
    "MITRE": [
        {
            "q": "MITRE ATT&CK 프레임워크의 구성 요소를 설명해주세요.",
            "a": "Tactics(전술): 공격 목적, Techniques(기술): 목적 달성 방법, Procedures(절차): 구체적인 구현 방법으로 구성됩니다."
        },
        {
            "q": "Initial Access 전술에 해당하는 기술 3가지는?",
            "a": "Phishing, Exploit Public-Facing Application, Valid Accounts, Supply Chain Compromise 등이 있습니다."
        },
        {
            "q": "Persistence 기법 3가지를 설명해주세요.",
            "a": "Registry Run Keys, Scheduled Task, Services, Startup Folder, DLL Hijacking 등이 있습니다."
        },
    ]
}

# 보안 용어 사전
SECURITY_TERMS = {
    "IOC": "Indicator of Compromise, 침해 지표. IP, 해시, 도메인 등 악성 활동의 흔적을 나타내는 정보입니다.",
    "TTP": "Tactics, Techniques, Procedures. 공격자의 행동 패턴을 설명하는 프레임워크입니다.",
    "APT": "Advanced Persistent Threat, 지능형 지속 위협. 특정 목표를 장기간 공격하는 고도화된 위협 그룹입니다.",
    "C2": "Command & Control, 명령제어 서버. 악성코드가 공격자와 통신하는 서버입니다.",
    "EDR": "Endpoint Detection and Response, 엔드포인트 위협 탐지 및 대응 솔루션입니다.",
    "SIEM": "Security Information and Event Management, 보안 정보 및 이벤트 관리 시스템입니다.",
    "SOAR": "Security Orchestration, Automation and Response, 보안 오케스트레이션 및 자동화 대응입니다.",
    "lateral movement": "측면 이동. 공격자가 내부 네트워크에서 다른 시스템으로 이동하는 기법입니다.",
    "living off the land": "LOLBins, 시스템에 기본 설치된 도구를 악용하는 공격 기법입니다.",
    "fileless malware": "파일리스 악성코드. 디스크에 파일을 남기지 않고 메모리에서만 실행됩니다.",
    "DGA": "Domain Generation Algorithm, 도메인 생성 알고리즘. C2 서버 탐지를 피하기 위해 도메인을 자동 생성합니다.",
    "beaconing": "비콘, 악성코드가 C2 서버에 주기적으로 연결하는 행위입니다.",
    "MFT": "Master File Table, NTFS 파일시스템의 모든 파일 메타데이터를 담고 있는 테이블입니다.",
    "prefetch": "Windows에서 프로그램 실행 속도를 높이기 위한 캐시 파일입니다. 실행 흔적 분석에 유용합니다.",
    "shimcache": "Application Compatibility Cache, 프로그램 실행 흔적을 기록하는 레지스트리 키입니다.",
    "amcache": "프로그램 설치 및 실행 정보를 저장하는 Windows 레지스트리 하이브입니다.",
    "usnjrnl": "NTFS Change Journal, 파일시스템 변경 사항을 기록하는 저널입니다.",
    "volatility": "메모리 포렌식 분석 도구입니다. 메모리 덤프에서 프로세스, 네트워크 등을 분석합니다.",
    "yara": "악성코드 패턴 매칭 도구입니다. 시그니처 기반으로 악성 파일을 탐지합니다.",
    "chain of custody": "연계보관성. 증거물의 수집부터 법정 제출까지 모든 과정을 문서화하는 것입니다.",
}

# 도구 사용법
TOOL_GUIDES = {
    "volatility": """
🔧 **Volatility 3 기본 사용법**
```
# 이미지 정보 확인
vol -f memory.dmp windows.info

# 프로세스 목록
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree

# 네트워크 연결
vol -f memory.dmp windows.netstat

# DLL 목록
vol -f memory.dmp windows.dlllist

# 악성코드 탐지
vol -f memory.dmp windows.malfind

# 파일 추출
vol -f memory.dmp windows.dumpfiles
```
""",
    "autopsy": """
🔧 **Autopsy 기본 사용법**

1. New Case 생성
2. Data Source 추가 (이미지 파일)
3. Ingest Modules 선택:
   - Recent Activity
   - Hash Lookup
   - Keyword Search
   - Web Artifacts
4. 분석 결과 확인:
   - Data Artifacts: 웹 기록, 다운로드 등
   - Timeline: 시간순 이벤트
   - Keyword Hits: 검색 결과
""",
    "wireshark": """
🔧 **Wireshark 기본 필터**
```
# IP 필터
ip.addr == 192.168.1.1
ip.src == 10.0.0.1

# 포트 필터
tcp.port == 80
udp.port == 53

# 프로토콜 필터
http
dns
tls

# HTTP 요청
http.request.method == "POST"

# DNS 쿼리
dns.qry.name contains "malware"

# 특정 문자열
frame contains "password"
```
""",
    "yara": """
🔧 **YARA 기본 사용법**
```yara
rule detect_malware {
    meta:
        author = "analyst"
        description = "악성코드 탐지 룰"
    
    strings:
        $str1 = "malicious" nocase
        $str2 = { 4D 5A 90 00 }  // MZ header
        $str3 = /http:\/\/[a-z]+\.com/
    
    condition:
        $str2 at 0 and any of ($str1, $str3)
}
```

실행: `yara rule.yar target_file`
""",
}

def get_random_question(category=None):
    """랜덤 면접 질문"""
    if category and category in DFIR_QUESTIONS:
        q_list = DFIR_QUESTIONS[category]
    else:
        # 전체에서 랜덤
        q_list = []
        for cat_questions in DFIR_QUESTIONS.values():
            q_list.extend(cat_questions)
    
    item = random.choice(q_list)
    return item['q'], item['a']

def get_question_categories():
    """질문 카테고리 목록"""
    return list(DFIR_QUESTIONS.keys())

def get_term_definition(term):
    """용어 정의 조회"""
    term_lower = term.lower()
    
    for key, definition in SECURITY_TERMS.items():
        if term_lower in key.lower() or key.lower() in term_lower:
            return f"📖 **{key.upper()}**\n\n{definition}"
    
    return None

def get_tool_guide(tool):
    """도구 가이드 조회"""
    tool_lower = tool.lower()
    
    for key, guide in TOOL_GUIDES.items():
        if tool_lower in key.lower() or key.lower() in tool_lower:
            return guide
    
    return None

def get_all_terms():
    """모든 용어 목록"""
    result = "📚 **보안 용어 목록**\n\n"
    for term in sorted(SECURITY_TERMS.keys()):
        result += f"• {term}\n"
    return result

def get_all_tools():
    """모든 도구 가이드 목록"""
    result = "🔧 **도구 가이드 목록**\n\n"
    for tool in sorted(TOOL_GUIDES.keys()):
        result += f"• {tool}\n"
    result += "\n'[도구명] 사용법' 으로 검색하세요."
    return result