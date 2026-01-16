# Security Bot 개발 가이드

**Telegram 기반 보안 학습 & 위협 인텔리전스 자동화 봇**

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [시스템 아키텍처](#2-시스템-아키텍처)
3. [핵심 기술 스택](#3-핵심-기술-스택)
4. [모듈별 상세 설명](#4-모듈별-상세-설명)
5. [자동화 시스템](#5-자동화-시스템)
6. [장점 및 활용](#6-장점-및-활용)
7. [직접 만들어보기](#7-직접-만들어보기)
8. [확장 아이디어](#8-확장-아이디어)

---

## 1. 프로젝트 개요

### 1.1 무엇을 하는 봇인가?

Security Bot은 **보안 전문가/학습자를 위한 Telegram 기반 AI 비서**입니다.

**주요 기능:**
- 실시간 보안 뉴스 수집 (국내/해외)
- CVE(취약점) 정보 모니터링
- DFIR(Digital Forensics & Incident Response) 퀴즈
- 보안 용어 사전 & 도구 가이드
- 긴급 취약점 자동 알림

### 1.2 왜 만들었는가?

| 문제점 | 해결책 |
|--------|--------|
| 보안 뉴스가 여러 사이트에 분산 | RSS로 한곳에 수집 |
| CVE 모니터링이 번거로움 | NVD API로 자동 수집 |
| DFIR 면접 준비가 어려움 | 퀴즈 시스템으로 반복 학습 |
| 매일 뉴스 체크를 까먹음 | 스케줄러로 자동 브리핑 |

### 1.3 대상 사용자

- 보안 분야 취업 준비생
- DFIR/SOC 분석가
- 보안 자격증 준비생 (정보보안기사, GCFA 등)
- 보안에 관심 있는 개발자

---

## 2. 시스템 아키텍처

### 2.1 전체 구조

```
┌─────────────────────────────────────────────────────────────┐
│                      사용자 (Telegram)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │ 메시지
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    bot.py (메인 컨트롤러)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Telegram    │  │ Gemini AI   │  │ Scheduler   │          │
│  │ Bot API     │  │ (자연어처리)  │  │ (자동화)     │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
┌─────────────────┐             ┌─────────────────┐
│  news_tool.py   │             │  study_tool.py  │
│  ┌───────────┐  │             │  ┌───────────┐  │
│  │ RSS 수집   │  │             │  │ 퀴즈 뱅크  │  │
│  │ CVE API   │  │             │  │ 용어 사전  │  │
│  │ 뉴스 파싱  │  │             │  │ 도구 가이드 │  │
│  └───────────┘  │             │  └───────────┘  │
└────────┬────────┘             └─────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    외부 데이터 소스                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ Hacker   │ │ Bleeping │ │ 보안뉴스  │ │ NVD API  │        │
│  │ News     │ │ Computer │ │ 데일리시큐 │ │ (CVE)    │        │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 데이터 흐름

```
1. 사용자 입력: "보안 뉴스 알려줘"
                    │
2. Telegram API ────┤
                    ▼
3. Gemini AI: 자연어 → [ACTION:NEWS]
                    │
4. 액션 파싱 ────────┤
                    ▼
5. news_tool.py: RSS 피드 수집
                    │
6. 결과 반환 ────────┤
                    ▼
7. 사용자에게 응답
```

---

## 3. 핵심 기술 스택

### 3.1 사용 기술

| 기술 | 역할 | 선택 이유 |
|------|------|-----------|
| **Python 3.10+** | 메인 언어 | 풍부한 라이브러리, 빠른 개발 |
| **python-telegram-bot** | Telegram 봇 API | 공식 지원, 비동기 처리 |
| **Google Gemini** | 자연어 처리 | 무료 API, 한국어 지원 |
| **feedparser** | RSS 파싱 | 표준 RSS 라이브러리 |
| **APScheduler** | 작업 스케줄링 | 비동기 지원, cron 문법 |
| **requests** | HTTP 클라이언트 | API 호출 |
| **BeautifulSoup** | HTML 파싱 | 웹 크롤링 시 사용 |

### 3.2 API 활용

```
┌─────────────────────────────────────────────────────────┐
│                     사용하는 API                          │
├─────────────────────────────────────────────────────────┤
│ 1. Telegram Bot API                                      │
│    - 메시지 송수신                                        │
│    - 명령어 처리                                          │
│                                                          │
│ 2. Google Gemini API                                     │
│    - 자연어 이해                                          │
│    - 보안 질문 답변                                       │
│                                                          │
│ 3. NVD (National Vulnerability Database) API             │
│    - CVE 정보 조회                                        │
│    - CVSS 점수 확인                                       │
│                                                          │
│ 4. RSS Feeds                                             │
│    - The Hacker News                                     │
│    - BleepingComputer                                    │
│    - 보안뉴스, 데일리시큐                                   │
│    - ASEC 블로그 (안랩)                                   │
└─────────────────────────────────────────────────────────┘
```

---

## 4. 모듈별 상세 설명

### 4.1 bot.py - 메인 컨트롤러

#### 역할
- Telegram 봇 실행
- 사용자 메시지 수신 및 응답
- AI를 통한 의도 파악
- 스케줄러 관리

#### 핵심 코드 분석

**1) AI 프롬프트 엔지니어링**

```python
SYSTEM_PROMPT = """너는 DFIR/보안 학습 도우미야.
사용자의 메시지를 분석해서 아래 형식으로 응답해.

[액션 형식]
- 보안 뉴스: [ACTION:NEWS]
- CVE 정보: [ACTION:CVE]
- DFIR 퀴즈: [ACTION:QUIZ]
- 용어 설명: [ACTION:TERM|용어]
...
"""
```

**왜 이렇게 설계했는가?**
- AI가 자연어를 **구조화된 명령**으로 변환
- 파싱이 쉬운 태그 형식 (`[ACTION:XXX]`)
- 정해진 형식이 없으면 일반 대화로 처리

**2) 액션 파싱 로직**

```python
async def handle_message(update, context):
    # AI 응답 받기
    ai_response = model.generate_content(prompt).text

    # 액션별 분기 처리
    if '[ACTION:NEWS]' in ai_response:
        result = get_daily_briefing()  # 뉴스 수집

    elif '[ACTION:QUIZ|' in ai_response:
        category = ai_response.split('[ACTION:QUIZ|')[1].split(']')[0]
        question, answer = get_random_question(category)
        quiz_state[chat_id] = answer  # 정답 저장

    elif '[ACTION:TERM|' in ai_response:
        term = ai_response.split('[ACTION:TERM|')[1].split(']')[0]
        result = get_term_definition(term)
```

**설계 포인트:**
- `split()`으로 간단하게 파라미터 추출
- `quiz_state` 딕셔너리로 사용자별 정답 관리
- 용어가 사전에 없으면 AI에게 직접 질문

**3) 비동기 처리**

```python
async def handle_message(update, context):
    # async/await로 비동기 처리
    await update.message.reply_text(result)
```

**왜 비동기인가?**
- 여러 사용자 동시 처리
- API 호출 대기 시간 동안 다른 작업 가능
- Telegram 봇 라이브러리가 비동기 기반

---

### 4.2 news_tool.py - 뉴스 & CVE 수집

#### 역할
- RSS 피드 파싱
- NVD API로 CVE 조회
- 브리핑 생성

#### 핵심 코드 분석

**1) RSS 피드 수집**

```python
import feedparser

def get_hacker_news(limit=5):
    """The Hacker News RSS 수집"""
    feed = feedparser.parse("https://feeds.feedburner.com/TheHackersNews")

    articles = []
    for entry in feed.entries[:limit]:
        articles.append({
            'title': entry.title,
            'link': entry.link,
            'date': entry.get('published', '')[:16]
        })

    return articles
```

**RSS(Really Simple Syndication)란?**
- 웹사이트의 콘텐츠를 구조화된 XML로 제공
- 별도 크롤링 없이 데이터 수집 가능
- 대부분의 뉴스 사이트가 제공

**2) CVE 수집 (NVD API)**

```python
def get_recent_cves(limit=5):
    """NVD에서 최신 CVE 수집"""
    # 최근 7일 범위 설정
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
        'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
        'resultsPerPage': 20
    }

    response = requests.get(url, params=params, timeout=15)
    data = response.json()

    cves = []
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve', {})

        # CVSS 점수 추출
        metrics = cve.get('metrics', {})
        cvss_data = metrics.get('cvssMetricV31', [{}])[0]
        base_score = cvss_data.get('cvssData', {}).get('baseScore', 0)

        # HIGH 이상만 (7.0+)
        if base_score >= 7.0:
            cves.append({
                'id': cve.get('id'),
                'score': base_score,
                'description': cve.get('descriptions', [{}])[0].get('value', '')
            })

    return sorted(cves, key=lambda x: x['score'], reverse=True)[:limit]
```

**NVD API 핵심 개념:**
- NVD: 미국 국립 취약점 데이터베이스
- CVSS: 취약점 심각도 점수 (0~10)
  - 9.0+ : Critical (긴급)
  - 7.0+ : High (높음)
  - 4.0+ : Medium (중간)
  - 0.1+ : Low (낮음)

**3) 브리핑 생성**

```python
def get_daily_briefing():
    """일일 보안 브리핑 생성"""
    briefing = "🛡️ **일일 보안 브리핑**\n"
    briefing += f"📆 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"

    # 여러 소스에서 수집
    briefing += "📰 **The Hacker News**\n"
    for article in get_hacker_news(3):
        briefing += f"• {article['title'][:60]}...\n"

    briefing += "🇰🇷 **보안뉴스**\n"
    for article in get_boannews(3):
        briefing += f"• {article['title'][:50]}...\n"

    # CVE 추가
    cves = get_recent_cves(3)
    if cves:
        briefing += "🚨 **주요 CVE**\n"
        for cve in cves:
            briefing += f"• {cve['id']} (CVSS: {cve['score']})\n"

    return briefing
```

---

### 4.3 study_tool.py - 학습 도구

#### 역할
- DFIR 면접 질문 관리
- 보안 용어 사전
- 도구 사용법 가이드

#### 데이터 구조

**1) 퀴즈 뱅크**

```python
DFIR_QUESTIONS = {
    "기초": [
        {
            "q": "디지털 포렌식의 4대 원칙은?",
            "a": "정당성, 재현성, 신속성, 연계보관성"
        },
        # ...
    ],
    "윈도우": [
        {
            "q": "Windows 레지스트리 하이브 5가지는?",
            "a": "SAM, SECURITY, SYSTEM, SOFTWARE, NTUSER.DAT"
        },
        # ...
    ],
    "메모리": [...],
    "네트워크": [...],
    "악성코드": [...],
    "MITRE": [...]
}
```

**카테고리 설계:**
| 카테고리 | 내용 |
|----------|------|
| 기초 | 포렌식 원칙, IR 절차, 기본 개념 |
| 윈도우 | 레지스트리, Prefetch, MFT, 이벤트 로그 |
| 메모리 | Volatility, 프로세스 분석, 인젝션 탐지 |
| 네트워크 | C2 탐지, DNS 분석, Lateral Movement |
| 악성코드 | 정적/동적 분석, PE 구조, 파일리스 |
| MITRE | ATT&CK 프레임워크, 전술/기술 |

**2) 용어 사전**

```python
SECURITY_TERMS = {
    "IOC": "Indicator of Compromise, 침해 지표...",
    "TTP": "Tactics, Techniques, Procedures...",
    "APT": "Advanced Persistent Threat...",
    "C2": "Command & Control, 명령제어 서버...",
    "EDR": "Endpoint Detection and Response...",
    "lateral movement": "측면 이동. 내부 네트워크 이동 기법...",
    "MFT": "Master File Table, NTFS 메타데이터...",
    # ...
}
```

**3) 도구 가이드**

```python
TOOL_GUIDES = {
    "volatility": """
    🔧 **Volatility 3 기본 사용법**
    ```
    # 프로세스 목록
    vol -f memory.dmp windows.pslist

    # 네트워크 연결
    vol -f memory.dmp windows.netstat

    # 악성코드 탐지
    vol -f memory.dmp windows.malfind
    ```
    """,
    "wireshark": """...""",
    "yara": """...""",
}
```

---

## 5. 자동화 시스템

### 5.1 스케줄러 구조

```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

scheduler = AsyncIOScheduler(timezone="Asia/Seoul")

async def post_init(application):
    global bot_instance
    bot_instance = application.bot

    # 매일 아침 9시 브리핑
    scheduler.add_job(
        send_daily_security_briefing,
        CronTrigger(hour=9, minute=0)
    )

    # 6시간마다 긴급 CVE 체크
    scheduler.add_job(
        check_critical_cve,
        'interval',
        hours=6
    )

    scheduler.start()
```

### 5.2 자동화 기능

```
┌─────────────────────────────────────────────────────────┐
│                    자동화 스케줄                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ⏰ 매일 09:00 - 일일 보안 브리핑                         │
│     └─ 해외 뉴스 (Hacker News, BleepingComputer)         │
│     └─ 국내 뉴스 (보안뉴스, 데일리시큐)                    │
│     └─ 주요 CVE (CVSS 7.0+)                              │
│                                                          │
│  🔄 6시간마다 - 긴급 CVE 체크                             │
│     └─ CVSS 9.0 이상 발견 시 즉시 알림                    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 5.3 긴급 알림 로직

```python
async def check_critical_cve():
    """심각한 CVE 체크 (CVSS 9.0 이상)"""
    cves = get_recent_cves(limit=3)
    critical_cves = [c for c in cves if c['score'] >= 9.0]

    if critical_cves:
        settings = load_user_settings()
        for chat_id, user_settings in settings.items():
            if user_settings.get('alert_enabled', False):
                msg = "🚨 **긴급 CVE 알림**\n\n"
                for cve in critical_cves:
                    msg += f"**{cve['id']}** (CVSS: {cve['score']})\n"
                    msg += f"{cve['description'][:100]}...\n\n"

                await bot_instance.send_message(chat_id=int(chat_id), text=msg)
```

**알림 조건:**
- CVSS 9.0 이상 (Critical)
- 사용자가 알림 활성화한 경우만

---

## 6. 장점 및 활용

### 6.1 학습 측면

| 장점 | 설명 |
|------|------|
| **매일 반복 학습** | 아침 브리핑으로 최신 동향 파악 |
| **면접 준비** | DFIR 퀴즈로 핵심 개념 반복 |
| **용어 정리** | 모르는 용어 즉시 검색 |
| **도구 학습** | Volatility, Wireshark 등 사용법 |

### 6.2 실무 측면

| 장점 | 설명 |
|------|------|
| **위협 인텔리전스** | 최신 CVE 자동 모니터링 |
| **긴급 대응** | CVSS 9.0+ 즉시 알림 |
| **정보 통합** | 여러 소스를 한 곳에서 확인 |
| **시간 절약** | 수동 체크 불필요 |

### 6.3 기술 학습 측면

**이 프로젝트로 배울 수 있는 것:**

```
1. API 연동
   ├─ REST API 호출 (requests)
   ├─ RSS 피드 파싱 (feedparser)
   └─ 인증 처리 (API Key)

2. 봇 개발
   ├─ Telegram Bot API
   ├─ 명령어 핸들링
   └─ 비동기 프로그래밍 (async/await)

3. AI 활용
   ├─ 프롬프트 엔지니어링
   ├─ 자연어 → 구조화된 명령 변환
   └─ LLM API 연동

4. 자동화
   ├─ 스케줄러 (APScheduler)
   ├─ 크론 표현식
   └─ 백그라운드 작업

5. 데이터 처리
   ├─ JSON 파싱
   ├─ 데이터 필터링/정렬
   └─ 상태 관리
```

---

## 7. 직접 만들어보기

### 7.1 환경 설정

**1) 필수 패키지 설치**

```bash
pip install python-telegram-bot google-generativeai python-dotenv feedparser requests APScheduler beautifulsoup4
```

**2) Telegram Bot 생성**

1. Telegram에서 @BotFather 검색
2. `/newbot` 명령어 입력
3. 봇 이름 설정 (예: My Security Bot)
4. 봇 username 설정 (예: my_security_bot)
5. **토큰 저장** (예: `123456:ABC-DEF...`)

**3) Gemini API 키 발급**

1. [Google AI Studio](https://makersuite.google.com/app/apikey) 접속
2. "Create API Key" 클릭
3. **API 키 저장**

### 7.2 프로젝트 구조

```
security_bot/
├── bot.py              # 메인 봇 파일
├── news_tool.py        # 뉴스/CVE 수집
├── study_tool.py       # 퀴즈/용어 사전
├── requirements.txt    # 패키지 목록
└── .env                # 환경변수 (토큰 저장)
```

### 7.3 단계별 구현

**Step 1: 기본 봇 만들기**

```python
# bot.py - 최소 버전
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters

TELEGRAM_TOKEN = "YOUR_TOKEN"

async def start(update, context):
    await update.message.reply_text("안녕하세요! 보안 봇입니다.")

async def handle_message(update, context):
    text = update.message.text
    await update.message.reply_text(f"받은 메시지: {text}")

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT, handle_message))
    app.run_polling()

if __name__ == '__main__':
    main()
```

**Step 2: RSS 뉴스 수집 추가**

```python
# news_tool.py
import feedparser

def get_security_news():
    feed = feedparser.parse("https://feeds.feedburner.com/TheHackersNews")

    result = "📰 **보안 뉴스**\n\n"
    for entry in feed.entries[:5]:
        result += f"• {entry.title}\n"

    return result
```

**Step 3: AI 연동**

```python
import google.generativeai as genai

genai.configure(api_key="YOUR_GEMINI_KEY")
model = genai.GenerativeModel('gemini-2.0-flash')

async def handle_message(update, context):
    user_msg = update.message.text

    prompt = f"""보안 전문가로서 답변해줘.
    질문: {user_msg}"""

    response = model.generate_content(prompt)
    await update.message.reply_text(response.text)
```

**Step 4: 스케줄러 추가**

```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

scheduler = AsyncIOScheduler(timezone="Asia/Seoul")

async def morning_briefing():
    news = get_security_news()
    await bot.send_message(chat_id=YOUR_CHAT_ID, text=news)

# 매일 9시 실행
scheduler.add_job(morning_briefing, CronTrigger(hour=9))
scheduler.start()
```

### 7.4 실행

```bash
python bot.py
```

---

## 8. 확장 아이디어

### 8.1 기능 확장

| 아이디어 | 설명 |
|----------|------|
| **IOC 검색** | VirusTotal API 연동 |
| **악성코드 분석** | 파일 해시 조회 |
| **취약점 스캔** | Shodan API 연동 |
| **MITRE 매핑** | 공격 기법 자동 분류 |
| **리포트 생성** | PDF 보고서 자동 생성 |

### 8.2 데이터 소스 추가

```python
# 추가 가능한 RSS 피드
RSS_FEEDS = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Threatpost": "https://threatpost.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}
```

### 8.3 학습 데이터 확장

```python
# 추가 가능한 퀴즈 카테고리
추가_카테고리 = {
    "클라우드 보안": ["AWS 보안", "Azure 보안", "컨테이너 보안"],
    "웹 보안": ["OWASP Top 10", "XSS", "SQL Injection"],
    "암호학": ["대칭키", "비대칭키", "해시 함수"],
    "법률/규정": ["개인정보보호법", "GDPR", "정보통신망법"],
}
```

### 8.4 고급 기능

```python
# 1. 대화 컨텍스트 유지
from collections import defaultdict
conversation_history = defaultdict(list)

# 2. 사용자별 학습 통계
user_stats = {
    "quiz_count": 0,
    "correct_count": 0,
    "weak_categories": []
}

# 3. 알림 커스터마이징
notification_settings = {
    "briefing_time": "09:00",
    "cvss_threshold": 7.0,
    "keywords": ["ransomware", "zero-day"]
}
```

---

## 부록: 파일 구조 요약

```
security_bot/
│
├── bot.py                    # 메인 컨트롤러
│   ├── SYSTEM_PROMPT         # AI 프롬프트
│   ├── handle_message()      # 메시지 처리
│   ├── start()              # /start 명령어
│   └── scheduler             # 자동화 스케줄러
│
├── news_tool.py              # 뉴스 & CVE
│   ├── get_hacker_news()    # 해커뉴스 RSS
│   ├── get_boannews()       # 보안뉴스 RSS
│   ├── get_recent_cves()    # NVD API
│   └── get_daily_briefing() # 브리핑 생성
│
├── study_tool.py             # 학습 도구
│   ├── DFIR_QUESTIONS       # 퀴즈 뱅크
│   ├── SECURITY_TERMS       # 용어 사전
│   ├── TOOL_GUIDES          # 도구 가이드
│   └── get_random_question() # 랜덤 퀴즈
│
└── requirements.txt          # 의존성 패키지
```

---

## 마무리

이 프로젝트는 다음을 보여줍니다:

1. **실용적인 봇 개발** - Telegram으로 일상에서 사용
2. **API 활용 능력** - REST API, RSS, AI 연동
3. **자동화 구현** - 스케줄러로 반복 작업 자동화
4. **보안 도메인 지식** - DFIR, 위협 인텔리전스

**포트폴리오 활용 팁:**
- GitHub에 코드 공개 (토큰은 환경변수로!)
- README에 스크린샷 추가
- 확장 기능 구현해서 차별화

---

*작성일: 2026-01-17*
*대상: 대학교 4학년 / 보안 취업 준비생*
