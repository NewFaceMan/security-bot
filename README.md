# Security Bot

Telegram 기반 보안 학습 & 위협 인텔리전스 봇

## 주요 기능

- **보안 뉴스 수집** - The Hacker News, BleepingComputer, 보안뉴스, 데일리시큐
- **CVE 모니터링** - NVD API로 최신 취약점 정보 (CVSS 7.0+)
- **DFIR 퀴즈** - 6개 분야 면접 대비 문제 (기초, 윈도우, 메모리, 네트워크, 악성코드, MITRE)
- **보안 용어 사전** - IOC, TTP, APT 등 주요 용어 설명
- **도구 가이드** - Volatility, Wireshark, YARA 사용법
- **자동 알림** - 매일 아침 브리핑, 긴급 CVE(CVSS 9.0+) 알림

## 스크린샷

```
🛡️ 일일 보안 브리핑
📆 2025-01-17 09:00

📰 The Hacker News
• Critical RCE Vulnerability Found in...
• New Ransomware Campaign Targets...

🇰🇷 보안뉴스
• 북한 해커 조직, 새로운 공격 기법...

🚨 주요 CVE (HIGH+)
• CVE-2025-1234 (CVSS: 9.8)
• CVE-2025-5678 (CVSS: 8.5)
```

## 설치

### 1. 클론

```bash
git clone https://github.com/NewFaceMan/security-bot.git
cd security-bot
```

### 2. 패키지 설치

```bash
pip install -r requirements.txt
```

### 3. 환경변수 설정

```bash
cp .env.example .env
```

`.env` 파일 편집:
```
TELEGRAM_TOKEN=your_telegram_token_here
GEMINI_API_KEY=your_gemini_api_key_here
```

### 4. 실행

```bash
python bot.py
```

## API 키 발급

| API | 발급 링크 |
|-----|----------|
| Telegram Bot | [@BotFather](https://t.me/BotFather) |
| Google Gemini | [Google AI Studio](https://makersuite.google.com/app/apikey) |

## 사용법

### 명령어

| 명령어 | 설명 |
|--------|------|
| `/start` | 봇 시작 |
| `/news` | 보안 뉴스 |
| `/cve` | 최신 CVE |
| `/quiz` | DFIR 퀴즈 |
| `/terms` | 용어 목록 |
| `/tools` | 도구 목록 |
| `/alert` | 알림 켜기/끄기 |

### 자연어 대화

```
보안 뉴스 알려줘
CVE 알려줘
문제 내줘
윈도우 문제
IOC가 뭐야?
volatility 사용법
알림 켜줘
```

## 기술 스택

- Python 3.10+
- python-telegram-bot
- Google Gemini AI
- feedparser (RSS)
- APScheduler

## 문서

자세한 개발 가이드는 [Security_Bot_Guide.md](./Security_Bot_Guide.md)를 참고하세요.

## License

MIT License
