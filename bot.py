import os
import json
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from google import genai
from news_tool import get_daily_briefing, get_news_with_links, get_cve_details, get_recent_cves, get_single_cve
from study_tool import (
    get_random_question, get_question_categories, 
    get_term_definition, get_tool_guide, get_all_terms, get_all_tools,
    SECURITY_TERMS, TOOL_GUIDES
)
import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# 환경변수 로드
load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# 사용자 설정 파일
USER_SETTINGS_FILE = "security_user_settings.json"

# Gemini 설정
gemini_client = genai.Client(api_key=GEMINI_API_KEY)
GEMINI_MODEL = 'gemini-2.0-flash'

# 스케줄러
scheduler = AsyncIOScheduler(timezone="Asia/Seoul")

# 봇 인스턴스
bot_instance = None

# 퀴즈 상태 저장 (정답 확인용)
quiz_state = {}

# 시스템 프롬프트
SYSTEM_PROMPT = """너는 DFIR/보안 학습 도우미야.
사용자의 메시지를 분석해서 아래 형식으로 응답해.

[액션 형식]
- 보안 뉴스: [ACTION:NEWS]
- 상세 뉴스 (링크 포함): [ACTION:NEWS_DETAIL]
- CVE 정보: [ACTION:CVE]
- CVE 상세 분석 (AI 요약/대처/학습): [ACTION:CVE_ANALYSIS]
- 특정 CVE 분석: [ACTION:CVE_ANALYSIS|CVE-XXXX-XXXXX]
- 일일 브리핑: [ACTION:BRIEFING]
- DFIR 퀴즈: [ACTION:QUIZ]
- 특정 분야 퀴즈: [ACTION:QUIZ|분야명]
- 용어 설명: [ACTION:TERM|용어]
- 도구 사용법: [ACTION:TOOL|도구명]
- 용어 목록: [ACTION:TERM_LIST]
- 도구 목록: [ACTION:TOOL_LIST]
- 알림 켜기: [ACTION:ALERT_ON]
- 알림 끄기: [ACTION:ALERT_OFF]
- 정답 확인: [ACTION:ANSWER]
- 일반 질문: 직접 대답해줘

[분야명 종류]
기초, 윈도우, 메모리, 네트워크, 악성코드, MITRE

[예시]
- "보안 뉴스 알려줘" → [ACTION:NEWS]
- "CVE 알려줘" → [ACTION:CVE]
- "CVE 분석해줘" → [ACTION:CVE_ANALYSIS]
- "CVE-2024-12345 분석" → [ACTION:CVE_ANALYSIS|CVE-2024-12345]
- "최근 취약점 상세 분석" → [ACTION:CVE_ANALYSIS]
- "문제 내줘" → [ACTION:QUIZ]
- "윈도우 문제" → [ACTION:QUIZ|윈도우]
- "IOC가 뭐야?" → [ACTION:TERM|IOC]
- "volatility 사용법" → [ACTION:TOOL|volatility]
- "정답" → [ACTION:ANSWER]
- "lateral movement 설명해줘" → [ACTION:TERM|lateral movement]

보안/포렌식 관련 일반 질문은 직접 친절하게 답변해줘.
절대 마크다운(**, ##, ``` 등)을 사용하지 마. 일반 텍스트로만 답변해.
"""

def load_user_settings():
    if os.path.exists(USER_SETTINGS_FILE):
        with open(USER_SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_user_settings(settings):
    with open(USER_SETTINGS_FILE, 'w') as f:
        json.dump(settings, f)

def get_user_setting(chat_id, key, default=False):
    settings = load_user_settings()
    chat_id = str(chat_id)
    if chat_id in settings:
        return settings[chat_id].get(key, default)
    return default

def set_user_setting(chat_id, key, value):
    settings = load_user_settings()
    chat_id = str(chat_id)
    if chat_id not in settings:
        settings[chat_id] = {}
    settings[chat_id][key] = value
    save_user_settings(settings)

CVE_ANALYSIS_PROMPT = """당신은 사이버보안 전문가입니다. 아래 CVE 정보를 분석해서 정해진 형식으로 응답하세요.

[CVE 정보]
- CVE ID: {cve_id}
- CVSS 점수: {score}
- 공격 벡터: {attack_vector}
- 공격 복잡도: {attack_complexity}
- CWE: {cwe}
- 설명: {description}

[응답 형식 - 아래 형식을 정확히 지켜주세요]

📋 3줄 요약
1. (이 취약점이 무엇인지 한 줄)
2. (어떤 영향을 끼치는지 한 줄)
3. (위험도와 공격 가능성 한 줄)

🛡️ 대처 방안
• (즉시 해야 할 조치)
• (패치/업데이트 관련)
• (임시 완화 조치)
• (모니터링/탐지 방법)

📚 학습 포인트
• (이 CVE에서 배울 수 있는 보안 개념)
• (관련된 공격 기법 - MITRE ATT&CK 매핑 가능하면 포함)
• (방어자 관점에서의 교훈)
• (유사 취약점 예방을 위한 개발/운영 팁)

한국어로 답변하고, 각 항목은 구체적이고 실용적으로 작성하세요.
절대 마크다운(**, ##, ``` 등)을 사용하지 마세요. 일반 텍스트로만 작성하세요.
"""


async def analyze_cve_with_ai(cve_data):
    """Gemini AI로 CVE 상세 분석"""
    try:
        prompt = CVE_ANALYSIS_PROMPT.format(
            cve_id=cve_data['id'],
            score=cve_data['score'],
            attack_vector=cve_data.get('attack_vector', 'N/A'),
            attack_complexity=cve_data.get('attack_complexity', 'N/A'),
            cwe=', '.join(cve_data.get('cwe', [])) or 'N/A',
            description=cve_data['description']
        )

        response = gemini_client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        if response.candidates and response.candidates[0].content.parts:
            return response.text.strip()
        return None
    except Exception as e:
        print(f"CVE AI 분석 오류: {e}")
        return None


async def get_cve_full_analysis(limit=3):
    """CVE 목록 + AI 상세 분석 통합"""
    cves = get_recent_cves(limit)

    if not cves:
        return "최근 주요 CVE가 없습니다."

    results = []
    for cve in cves:
        header = (
            f"🔴 {cve['id']} (CVSS: {cve['score']})\n"
            f"🔗 {cve['link']}\n"
            f"━━━━━━━━━━━━━━━\n"
        )

        ai_analysis = await analyze_cve_with_ai(cve)
        if ai_analysis:
            results.append(header + ai_analysis)
        else:
            results.append(header + f"{cve['description_short']}...\n(AI 분석 실패)")

    return results


async def send_daily_security_briefing():
    """매일 보안 브리핑 전송"""
    global bot_instance
    settings = load_user_settings()
    
    for chat_id, user_settings in settings.items():
        if user_settings.get('alert_enabled', False):
            briefing = get_daily_briefing()
            if bot_instance:
                try:
                    await bot_instance.send_message(chat_id=int(chat_id), text=briefing)
                except Exception as e:
                    print(f"브리핑 전송 실패: {e}")

async def check_critical_cve():
    """심각한 CVE 체크 (CVSS 9.0 이상)"""
    global bot_instance
    settings = load_user_settings()
    
    cves = get_recent_cves(limit=3)
    critical_cves = [c for c in cves if c['score'] >= 9.0]
    
    if critical_cves:
        # AI 분석 포함한 긴급 알림 생성
        analyzed_msgs = []
        for cve in critical_cves:
            header = f"🚨 긴급 CVE 알림\n━━━━━━━━━━━━━━━\n\n🔴 {cve['id']} (CVSS: {cve['score']})\n🔗 {cve['link']}\n\n"
            ai_analysis = await analyze_cve_with_ai(cve)
            if ai_analysis:
                analyzed_msgs.append(header + ai_analysis)
            else:
                analyzed_msgs.append(header + f"{cve['description'][:200]}...\n")

        for chat_id, user_settings in settings.items():
            if user_settings.get('alert_enabled', False):
                if bot_instance:
                    for msg in analyzed_msgs:
                        try:
                            await bot_instance.send_message(chat_id=int(chat_id), text=msg)
                        except:
                            pass

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    set_user_setting(chat_id, 'registered', True)
    
    await update.message.reply_text(
        "안녕하세요! 보안 학습 도우미입니다 🛡️\n"
        "━━━━━━━━━━━━━━━\n\n"
        "📰 뉴스 & 정보\n"
        "• 보안 뉴스 / 뉴스 상세\n"
        "• CVE 알려줘 (목록)\n"
        "• CVE 분석해줘 (AI 상세 분석)\n"
        "• CVE-XXXX-XXXXX 분석 (특정 CVE)\n"
        "• 브리핑\n\n"
        "📚 학습\n"
        "• 문제 내줘 (DFIR 퀴즈)\n"
        "• 윈도우/메모리/네트워크 문제\n"
        "• [용어] 가 뭐야?\n"
        "• [도구] 사용법\n\n"
        "🔔 알림\n"
        "• 알림 켜줘 (매일 아침 + CVE)\n\n"
        "💬 자유 질문\n"
        "• 보안/포렌식 관련 뭐든 물어보세요!\n\n"
        "무엇을 도와드릴까요?"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_message = update.message.text
    chat_id = update.effective_chat.id
    
    prompt = SYSTEM_PROMPT + f"\n\n사용자: {user_message}"
    
    try:
        response = gemini_client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        
        if not response.candidates or not response.candidates[0].content.parts:
            await update.message.reply_text("죄송해요, 이해하지 못했어요. 다시 말씀해주세요.")
            return
        
        ai_response = response.text.strip()
        print(f"DEBUG: {ai_response}")
        
        # 액션 파싱
        if '[ACTION:NEWS_DETAIL]' in ai_response:
            result = get_news_with_links()
            await update.message.reply_text(result, disable_web_page_preview=True)
        
        elif '[ACTION:NEWS]' in ai_response:
            result = get_daily_briefing()
            await update.message.reply_text(result)
        
        elif '[ACTION:CVE_ANALYSIS|' in ai_response:
            # 특정 CVE ID 분석
            target_cve_id = ai_response.split('[ACTION:CVE_ANALYSIS|')[1].split(']')[0].strip()
            await update.message.reply_text(f"🔍 {target_cve_id} 분석 중... 잠시만 기다려주세요.")
            cve_data = get_single_cve(target_cve_id)
            if cve_data:
                header = (
                    f"🔴 {cve_data['id']} (CVSS: {cve_data['score']})\n"
                    f"🔗 {cve_data['link']}\n"
                    f"━━━━━━━━━━━━━━━\n"
                )
                ai_analysis = await analyze_cve_with_ai(cve_data)
                if ai_analysis:
                    await update.message.reply_text(header + ai_analysis, disable_web_page_preview=True)
                else:
                    await update.message.reply_text(header + cve_data['description'], disable_web_page_preview=True)
            else:
                await update.message.reply_text(f"❌ {target_cve_id}를 찾을 수 없습니다. CVE ID를 확인해주세요.")

        elif '[ACTION:CVE_ANALYSIS]' in ai_response:
            # 최근 CVE 전체 분석
            await update.message.reply_text("🔍 최근 고위험 CVE를 분석 중... 잠시만 기다려주세요.")
            results = await get_cve_full_analysis(limit=3)
            if isinstance(results, str):
                await update.message.reply_text(results)
            else:
                for result in results:
                    await update.message.reply_text(result, disable_web_page_preview=True)

        elif '[ACTION:CVE]' in ai_response:
            result = get_cve_details()
            await update.message.reply_text(result, disable_web_page_preview=True)
        
        elif '[ACTION:BRIEFING]' in ai_response:
            result = get_daily_briefing()
            await update.message.reply_text(result)
        
        elif '[ACTION:QUIZ|' in ai_response:
            category = ai_response.split('[ACTION:QUIZ|')[1].split(']')[0].strip()
            question, answer = get_random_question(category)
            quiz_state[chat_id] = answer
            await update.message.reply_text(f"❓ 문제 ({category})\n━━━━━━━━━━━━━━━\n{question}\n\n'정답' 이라고 하면 답을 알려드릴게요!")
        
        elif '[ACTION:QUIZ]' in ai_response:
            question, answer = get_random_question()
            quiz_state[chat_id] = answer
            await update.message.reply_text(f"❓ 문제\n━━━━━━━━━━━━━━━\n{question}\n\n'정답' 이라고 하면 답을 알려드릴게요!")
        
        elif '[ACTION:ANSWER]' in ai_response:
            if chat_id in quiz_state:
                answer = quiz_state[chat_id]
                await update.message.reply_text(f"💡 정답\n━━━━━━━━━━━━━━━\n{answer}")
                del quiz_state[chat_id]
            else:
                await update.message.reply_text("먼저 '문제 내줘'로 퀴즈를 시작해주세요!")
        
        elif '[ACTION:TERM|' in ai_response:
            term = ai_response.split('[ACTION:TERM|')[1].split(']')[0].strip()
            result = get_term_definition(term)
            if result:
                await update.message.reply_text(result)
            else:
                # Gemini한테 직접 물어보기
                term_prompt = f"보안/포렌식 용어 '{term}'에 대해 간단히 설명해줘. 2-3문장으로."
                term_response = gemini_client.models.generate_content(model=GEMINI_MODEL, contents=term_prompt)
                await update.message.reply_text(f"📖 {term}\n━━━━━━━━━━━━━━━\n{term_response.text}")
        
        elif '[ACTION:TOOL|' in ai_response:
            tool = ai_response.split('[ACTION:TOOL|')[1].split(']')[0].strip()
            result = get_tool_guide(tool)
            if result:
                await update.message.reply_text(result)
            else:
                tool_prompt = f"보안/포렌식 도구 '{tool}'의 기본 사용법을 간단히 알려줘."
                tool_response = gemini_client.models.generate_content(model=GEMINI_MODEL, contents=tool_prompt)
                await update.message.reply_text(f"🔧 {tool}\n━━━━━━━━━━━━━━━\n{tool_response.text}")
        
        elif '[ACTION:TERM_LIST]' in ai_response:
            result = get_all_terms()
            await update.message.reply_text(result)
        
        elif '[ACTION:TOOL_LIST]' in ai_response:
            result = get_all_tools()
            await update.message.reply_text(result)
        
        elif '[ACTION:ALERT_ON]' in ai_response:
            set_user_setting(chat_id, 'alert_enabled', True)
            await update.message.reply_text("🔔 알림이 켜졌습니다!\n• 매일 아침 9시 보안 브리핑\n• 긴급 CVE(CVSS 9.0+) 알림")
        
        elif '[ACTION:ALERT_OFF]' in ai_response:
            set_user_setting(chat_id, 'alert_enabled', False)
            await update.message.reply_text("🔕 알림이 꺼졌습니다.")
        
        else:
            # 일반 대화 (ACTION 태그 제거)
            if '[ACTION' in ai_response:
                await update.message.reply_text("이해하지 못했어요. 다시 말씀해주세요.")
            else:
                await update.message.reply_text(ai_response)
    
    except Exception as e:
        error_msg = str(e)
        print(f"DEBUG ERROR: {error_msg}")
        if "response.text" in error_msg or "Part" in error_msg:
            await update.message.reply_text("죄송해요, 다시 한번 말씀해주세요.")
        else:
            await update.message.reply_text(f"오류가 발생했어요: {error_msg}")

async def news_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = get_daily_briefing()
    await update.message.reply_text(result)

async def cve_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = get_cve_details()
    await update.message.reply_text(result, disable_web_page_preview=True)

async def quiz_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    question, answer = get_random_question()
    quiz_state[chat_id] = answer
    await update.message.reply_text(f"❓ 문제\n━━━━━━━━━━━━━━━\n{question}\n\n'정답' 이라고 하면 답을 알려드릴게요!")

async def terms_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = get_all_terms()
    await update.message.reply_text(result)

async def tools_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = get_all_tools()
    await update.message.reply_text(result)

async def alert_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    current = get_user_setting(chat_id, 'alert_enabled', False)
    set_user_setting(chat_id, 'alert_enabled', not current)
    
    if not current:
        await update.message.reply_text("🔔 알림이 켜졌습니다!")
    else:
        await update.message.reply_text("🔕 알림이 꺼졌습니다.")

async def post_init(application):
    global bot_instance
    bot_instance = application.bot
    
    # 매일 아침 9시 브리핑 (하루 1회)
    scheduler.add_job(send_daily_security_briefing, CronTrigger(hour=9, minute=0))
    scheduler.start()
    print("⏰ 스케줄러 시작됨")

def main():
    print("🛡️ 보안 학습 봇 시작 중...")
    
    app = Application.builder().token(TELEGRAM_TOKEN).post_init(post_init).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("news", news_cmd))
    app.add_handler(CommandHandler("cve", cve_cmd))
    app.add_handler(CommandHandler("quiz", quiz_cmd))
    app.add_handler(CommandHandler("terms", terms_cmd))
    app.add_handler(CommandHandler("tools", tools_cmd))
    app.add_handler(CommandHandler("alert", alert_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("✅ 보안 학습 봇이 실행되었습니다!")
    app.run_polling()

if __name__ == '__main__':
    main()