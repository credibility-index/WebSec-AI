import asyncio
import aiohttp
import feedparser
import json
import os
from datetime import datetime

async def fetch_rss(session, url):
    try:
        async with session.get(url) as response:
            content = await response.text()
            return feedparser.parse(content)
    except Exception as e:
        print(f"Ошибка при загрузке RSS {url}: {e}")
        return None

async def parse_rss_feeds(urls, output_file):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_rss(session, url) for url in urls]
        feeds = await asyncio.gather(*tasks)

        with open(output_file, 'w', encoding='utf-8') as f:
            for feed in feeds:
                if feed:
                    for entry in feed.entries:
                        data = {
                            'title': entry.title,
                            'link': entry.link,
                            'summary': entry.summary,
                            'published': entry.get('published', str(datetime.now())),
                            'source': feed.feed.get('title', 'Unknown'),
                            'text': entry.get('content', [{}])[0].get('value', entry.summary) if entry.get('content') else entry.summary
                        }
                        f.write(json.dumps(data, ensure_ascii=False) + '\n')
        print(f"Парсинг завершён. Результат сохранён в {output_file}")
