"""Приведение ответа нейросети к виду, который хорошо звучит голосом.

Раньше это жило внутри local_ai.py рядом с запросами к Ollama. Теперь чат-движок
один — arena_ai.py, — а чистка текста общая и от движка не зависит.
"""
import re

# иероглифы и полноширинные символы: модели иногда срываются на другой язык
FOREIGN = re.compile(r"[　-鿿가-힯＀-￯]+")

THIRD_PERSON = re.compile(r"(одн(а|ой|у) прекрасн(ая|ой|ую) (я|мне|меня|мной))", re.IGNORECASE)

EMOJI = re.compile(r"[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F\u200D]")
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\((?:[^)]+)\)")
MARKDOWN = re.compile(r"[*_`#>|]+|^\s*[-–—•]\s+", re.MULTILINE)
REASONING = re.compile(r"^\W*(okay|ok,|alright|let me|the user|first,|хорошо,? (пользователь|мне|нужно|давай)|"
                       r"пользователь (спрашива|хочет|проси|пиш|говор)|мне нужно|нужно ответить|"
                       r"итак,? (пользователь|мне|нужно)|сначала (мне |нужно |надо )|давайте? (подума|разбер))",
                       re.IGNORECASE)

SELF_TALK = re.compile(r"\bя\s*[—–-]?\s*капри\b|меня зовут капри|\bкапри (здесь|тут|на связи)|^капри\b|"
                       r"\bне (просто |какой-то |обычный |обычная )?(бот|ии|программ\w*|голос в)|\bя не бот\b|"
                       r"сильнее (любого |обычного )?(бот|ии)|(называ|зови|счита)\w* меня (просто )?(бот|ии)|\bя ии\b|"
                       r"каприкорн", re.IGNORECASE)
ASKED_SELF = re.compile(r"кто ты|как тебя зовут|тво[её] имя|\bии\b|бот|программ|нейросет|о себе|про себя|"
                        r"ты кто|кто такая", re.IGNORECASE)


def drop_third_person(answer):
    """Страховка поверх промпта: Капри не говорит о себе в третьем лице. Такие предложения
    выкидываем целиком (чтобы не ломать согласование глаголов), а если других нет — меняем на «я»."""
    sentences = re.split(r"(?<=[.!?…])\s+", answer)
    clean = [s for s in sentences if not THIRD_PERSON.search(s)]
    if clean:
        return " ".join(clean)
    return THIRD_PERSON.sub("я", answer)


def naturalize(answer, question, recent):
    """Страховка поверх промпта — чтобы Капри звучала как собеседница, а не как персонаж,
    зацикленный на своих чертах: без самопредставлений и «я не бот» без повода, без «чумба» в каждой фразе."""
    parts = [p for p in re.split(r"(?<=[.!?…])\s+", answer) if p.strip()]
    if not ASKED_SELF.search(question.lower()):
        parts = [p for p in parts if not SELF_TALK.search(p)] or parts
    parts = [p for p in parts if not re.fullmatch(r"\W*чумба\W*", p.lower())] or parts
    text = " ".join(parts)
    # «чумба» — не чаще раза на несколько ответов
    allow = not any("чумба" in r.lower() for r in recent[-3:])
    used = []

    def keep_or_drop(m):
        if allow and not used:
            used.append(1)
            return m.group(0)
        return "," if m.group(1) and m.group(2) else ""
    text = re.sub(r"(,\s*)?\bчумба\b(\s*,)?", keep_or_drop, text, flags=re.IGNORECASE)
    text = re.sub(r"\s+([,.!?…])", r"\1", text)
    text = re.sub(r"(^|[.!?…]\s+)[,\s]+", r"\1", text)
    text = re.sub(r"(^|[.!?…]\s+)(\w)", lambda m: m.group(1) + m.group(2).upper(), text)
    return text.strip() or answer


ROLEPLAY = re.compile(r"^\W*(вздыха|вздох|улыба|усмеха|смеюсь|смеётся|хихика|пожима|закатыва|"
                      r"подмигива|потягива|бормоч|шепч)", re.IGNORECASE)


def drop_roleplay(answer):
    """Убирает ремарки-действия («Вздыхаю…», «Улыбаюсь»), которые синтезатор прочитает вслух."""
    parts = [p for p in re.split(r"(?<=[.!?…])\s+", answer) if p.strip()]
    kept = [p for p in parts if not ROLEPLAY.match(p)]
    return " ".join(kept) or answer


def strip_reasoning(text):
    """Убирает «мысли вслух»: блоки <think>…</think>, хвост до одинокого </think>
    (у новых Qwen открывающей метки нет) и незакрытый <think> до конца."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    if "</think>" in text:
        text = text.rsplit("</think>", 1)[1]
    return re.sub(r"<think>.*", "", text, flags=re.S).strip()


def clean(answer, question, history):
    """Полная чистка ответа перед озвучкой: рассуждения, иероглифы, markdown, третье лицо,
    ремарки-действия и скобки, эмодзи, лишние пробелы."""
    text = strip_reasoning(answer or "")
    text = FOREIGN.sub("", text)
    text = MARKDOWN_LINK.sub(r"\1", text)
    text = MARKDOWN.sub(" ", text)      # раньше, чем делим на предложения: «**Привет!**» ≠ «Привет!»
    text = drop_third_person(text)
    text = drop_roleplay(text)
    recent = [m.get("content", "") for m in history if m.get("role") == "assistant"]
    text = naturalize(text, question, recent)
    text = re.sub(r"\s*\([^)]*\)", "", text)          # ремарки в скобках
    text = MARKDOWN.sub(" ", text)
    text = EMOJI.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    if text:
        text = text[:1].upper() + text[1:]
    return text


def looks_broken(answer):
    """Ответ, который нельзя озвучивать: пустой, оборванный или похож на «не могу»."""
    if not answer:
        return True
    if len(answer) < 40 and not re.search(r"[.!?…]$", answer):
        return True
    return False


def clean_short(text, min_len=5, max_len=160):
    """Короткая реплика (chatter): одна фраза без markdown, эмодзи и рассуждений."""
    text = strip_reasoning(text or "")
    text = FOREIGN.sub("", text)
    text = MARKDOWN_LINK.sub(r"\1", text)
    text = MARKDOWN.sub(" ", text)
    text = EMOJI.sub("", text)
    text = text.strip().strip('"«»').strip()
    text = re.sub(r"\s+", " ", text)
    return text if min_len < len(text) < max_len and re.search(r"[.!?…]$", text) else None
