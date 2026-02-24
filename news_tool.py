import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import re

# 보안 위협 관련 키워드 (이 키워드가 포함된 기사만 필터링)
THREAT_KEYWORDS = [
    # 공격/위협
    '취약점', '해킹', '해커', '랜섬웨어', '악성코드', '멀웨어', '피싱', '스미싱',
    '침해', '공격', '유출', '탈취', '감염', '익스플로잇', '백도어', '트로이목마',
    # 기술 용어
    'CVE', 'APT', 'DDoS', '제로데이', '0-day', 'RCE', 'XSS', 'SQL인젝션',
    '버퍼오버플로우', '권한상승', '원격코드', '인젝션',
    # 대상
    '북한', '중국', '러시아', '사이버전', '국가지원',
    # 기타
    '보안패치', '긴급패치', '업데이트 권고', '주의보', '경보'
]

def contains_threat_keyword(title):
    """제목에 위협 키워드가 포함되어 있는지 확인"""
    title_lower = title.lower()
    for keyword in THREAT_KEYWORDS:
        if keyword.lower() in title_lower:
            return True
    return False

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

def get_bleeping_computer(limit=5):
    """BleepingComputer RSS 수집"""
    feed = feedparser.parse("https://www.bleepingcomputer.com/feed/")
    
    articles = []
    for entry in feed.entries[:limit]:
        articles.append({
            'title': entry.title,
            'link': entry.link,
            'date': entry.get('published', '')[:16]
        })
    
    return articles

def get_reddit_netsec(limit=5):
    """Reddit r/netsec 수집"""
    headers = {'User-Agent': 'SecurityBot/1.0'}
    
    try:
        response = requests.get(
            "https://www.reddit.com/r/netsec/hot.json?limit=10",
            headers=headers,
            timeout=10
        )
        data = response.json()
        
        articles = []
        for post in data['data']['children'][:limit]:
            p = post['data']
            if not p.get('stickied'):  # 고정글 제외
                articles.append({
                    'title': p['title'][:100],
                    'link': f"https://reddit.com{p['permalink']}",
                    'score': p['score']
                })
        
        return articles
    except:
        return []

def get_kisa_notices(limit=5):
    """ASEC 블로그 (안랩) 수집 - 한국 위협 정보"""
    try:
        feed = feedparser.parse("https://asec.ahnlab.com/ko/feed/")
        
        articles = []
        for entry in feed.entries[:limit]:
            articles.append({
                'title': entry.title,
                'link': entry.link,
            })
        
        return articles
    except Exception as e:
        print(f"ASEC 수집 오류: {e}")
        return []
    
def get_boannews(limit=5):
    """보안뉴스 RSS 수집 (위협 키워드 필터링)"""
    try:
        feed = feedparser.parse("https://www.boannews.com/media/news_rss.xml")

        articles = []
        for entry in feed.entries:
            if contains_threat_keyword(entry.title):
                articles.append({
                    'title': entry.title,
                    'link': entry.link,
                })
                if len(articles) >= limit:
                    break

        return articles
    except Exception as e:
        print(f"보안뉴스 수집 오류: {e}")
        return []

def get_dailysecu(limit=5):
    """데일리시큐 RSS 수집 (위협 키워드 필터링)"""
    try:
        feed = feedparser.parse("https://www.dailysecu.com/rss/allArticle.xml")

        articles = []
        for entry in feed.entries:
            if contains_threat_keyword(entry.title):
                articles.append({
                    'title': entry.title,
                    'link': entry.link,
                })
                if len(articles) >= limit:
                    break

        return articles
    except Exception as e:
        print(f"데일리시큐 수집 오류: {e}")
        return []

def get_recent_cves(limit=5, severity="HIGH"):
    """NVD에서 최신 CVE 수집"""
    try:
        # 최근 7일
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
            cve_id = cve.get('id', '')
            
            # 심각도 확인
            metrics = cve.get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
            base_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
            
            if base_score >= 7.0:  # HIGH 이상만
                desc = cve.get('descriptions', [{}])[0].get('value', '')
                # 영문 설명 우선, 없으면 첫 번째 설명
                for d in cve.get('descriptions', []):
                    if d.get('lang') == 'en':
                        desc = d.get('value', '')
                        break

                # CWE (취약점 유형) 추출
                weaknesses = cve.get('weaknesses', [])
                cwe_ids = []
                for w in weaknesses:
                    for wd in w.get('description', []):
                        if wd.get('value', '').startswith('CWE-'):
                            cwe_ids.append(wd['value'])

                # 공격 벡터 정보 추출
                attack_vector = cvss_data.get('cvssData', {}).get('attackVector', '')
                attack_complexity = cvss_data.get('cvssData', {}).get('attackComplexity', '')

                cves.append({
                    'id': cve_id,
                    'score': base_score,
                    'description': desc,
                    'description_short': desc[:200],
                    'link': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    'cwe': cwe_ids,
                    'attack_vector': attack_vector,
                    'attack_complexity': attack_complexity,
                })
        
        # 점수 높은 순 정렬
        cves.sort(key=lambda x: x['score'], reverse=True)
        return cves[:limit]
    
    except Exception as e:
        print(f"CVE 수집 오류: {e}")
        return []

def get_daily_briefing():
    """일일 보안 브리핑 생성"""
    briefing = "🛡️ 일일 보안 브리핑\n"
    briefing += f"📆 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
    briefing += "━━━━━━━━━━━━━━━\n\n"

    # 해커뉴스
    briefing += "📰 The Hacker News\n"
    for article in get_hacker_news(3):
        briefing += f"• {article['title'][:60]}...\n"
    briefing += "\n"

    # 보안뉴스 (한국)
    briefing += "🇰🇷 보안뉴스\n"
    for article in get_boannews(3):
        briefing += f"• {article['title'][:50]}...\n"
    briefing += "\n"

    # 데일리시큐 (한국)
    briefing += "🇰🇷 데일리시큐\n"
    for article in get_dailysecu(3):
        briefing += f"• {article['title'][:50]}...\n"
    briefing += "\n"

    # BleepingComputer
    briefing += "💻 BleepingComputer\n"
    for article in get_bleeping_computer(3):
        briefing += f"• {article['title'][:60]}...\n"
    briefing += "\n"

    # CVE
    cves = get_recent_cves(3)
    if cves:
        briefing += "🚨 주요 CVE (HIGH+)\n"
        for cve in cves:
            briefing += f"• {cve['id']} (CVSS: {cve['score']})\n"

    return briefing

def get_news_with_links(source="all", limit=5):
    """링크 포함 뉴스 조회"""
    result = ""

    if source in ["all", "hackernews"]:
        result += "📰 The Hacker News\n"
        for article in get_hacker_news(limit):
            result += f"• {article['title'][:50]}...\n  {article['link']}\n"
        result += "\n"

    if source in ["all", "boannews"]:
        result += "🇰🇷 보안뉴스\n"
        for article in get_boannews(limit):
            result += f"• {article['title'][:50]}...\n  {article['link']}\n"
        result += "\n"

    if source in ["all", "dailysecu"]:
        result += "🇰🇷 데일리시큐\n"
        for article in get_dailysecu(limit):
            result += f"• {article['title'][:50]}...\n  {article['link']}\n"
        result += "\n"

    if source in ["all", "bleeping"]:
        result += "💻 BleepingComputer\n"
        for article in get_bleeping_computer(limit):
            result += f"• {article['title'][:50]}...\n  {article['link']}\n"
        result += "\n"

    if source in ["all", "reddit"]:
        result += "🔥 Reddit r/netsec\n"
        for article in get_reddit_netsec(limit):
            result += f"• {article['title'][:50]}...\n  {article['link']}\n"
        result += "\n"

    if source in ["all", "kisa"]:
        result += "🇰🇷 ASEC 블로그 (안랩)\n"
        for article in get_kisa_notices(limit):
            result += f"• {article['title'][:50]}...\n  {article['link']}\n"
        result += "\n"

    return result if result else "뉴스를 가져오지 못했습니다."

def get_cve_details(limit=5):
    """CVE 상세 정보 (간단 목록)"""
    cves = get_recent_cves(limit)

    if not cves:
        return "최근 주요 CVE가 없습니다."

    result = "🚨 최근 주요 CVE (CVSS 7.0+)\n━━━━━━━━━━━━━━━\n\n"
    for cve in cves:
        result += f"🔴 {cve['id']} (CVSS: {cve['score']})\n"
        result += f"{cve['description_short']}...\n"
        result += f"🔗 {cve['link']}\n\n"

    result += "💡 'CVE 분석해줘' 또는 'CVE-XXXX-XXXXX 분석'으로\n"
    result += "   AI 상세 분석을 받아볼 수 있어요!"
    return result


def get_single_cve(cve_id):
    """특정 CVE ID로 단일 CVE 상세 정보 조회"""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cveId': cve_id}

        response = requests.get(url, params=params, timeout=15)
        data = response.json()

        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return None

        cve = vulns[0].get('cve', {})
        metrics = cve.get('metrics', {})
        cvss_data = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
        base_score = cvss_data.get('cvssData', {}).get('baseScore', 0)

        desc = ''
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break
        if not desc:
            desc = cve.get('descriptions', [{}])[0].get('value', '')

        weaknesses = cve.get('weaknesses', [])
        cwe_ids = []
        for w in weaknesses:
            for wd in w.get('description', []):
                if wd.get('value', '').startswith('CWE-'):
                    cwe_ids.append(wd['value'])

        attack_vector = cvss_data.get('cvssData', {}).get('attackVector', '')
        attack_complexity = cvss_data.get('cvssData', {}).get('attackComplexity', '')

        return {
            'id': cve.get('id', cve_id),
            'score': base_score,
            'description': desc,
            'description_short': desc[:200],
            'link': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'cwe': cwe_ids,
            'attack_vector': attack_vector,
            'attack_complexity': attack_complexity,
        }

    except Exception as e:
        print(f"CVE 조회 오류: {e}")
        return None