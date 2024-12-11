from collections import Counter

# Основной текст
with open('data/ciphertext1.txt', 'r') as file:
    ciphertext1 = file.read()

with open('data/ciphertext2.txt', 'r') as file:
    ciphertext2 = file.read()

with open('data/ciphertext3.txt', 'r') as file:
    ciphertext3 = file.read()

with open('data/ciphertext4.txt', 'r') as file:
    ciphertext4 = file.read()

# захватчиков
with open('data/ciphertext2.txt', 'r') as file:
    text2 = file.read()

# захватчиков
with open('data/ciphertext3.txt', 'r') as file:
    text3 = file.read()

# 1
with open('data/ciphertext4.txt', 'r') as file:
    text4 = file.read()

plaintexts = [
    text2, 
    text3, 
    text4
]

ciphertexts = [
    ciphertext2,
    ciphertext3,
    ciphertext4
]

# -------------------------------------------------------------------------------------------------------------------------------------

def find_repeated_chars(text):
    """
    Ищет повторяющиеся буквы в тексте.
    :param text: Исходный текст.
    :return: Список словарей с информацией о повторениях.
    """
    letters_info = {}
    
    for index, char in enumerate(text):
        if char.isalpha():  # Учитываем только буквы
            char = char.lower()  # Приводим к нижнему регистру для унификации
            if char not in letters_info:
                letters_info[char] = {'letter': char, 'count': 0, 'indices': []}
            letters_info[char]['count'] += 1
            letters_info[char]['indices'].append(index)
    
    return list(letters_info.values())


def find_repeated_substrings(text, min_length=2):
    """
    Ищет повторяющиеся подстроки в тексте.
    :param text: Исходный текст.
    :param min_length: Минимальная длина подстроки для анализа.
    :return: Список словарей с информацией о повторениях.
    """
    substrings = {}
    n = len(text)
    
    for start in range(n):
        for end in range(start + min_length, n + 1):
            substring = text[start:end]
            if substring in substrings:
                substrings[substring]['count'] += 1
                substrings[substring]['indices'].append(start)
            else:
                substrings[substring] = {
                    'substring': substring,
                    'count': 1,
                    'indices': [start]
                }
    
    # Возвращаем только повторяющиеся подстроки
    return [info for info in substrings.values() if info['count'] > 1]


def find_matching_chars(ciphertext1, ciphertext2):
    """
    Находит совпадающие символы на одинаковых позициях в двух шифротекстах.
    
    :param ciphertext1: Первый шифротекст.
    :param ciphertext2: Второй шифротекст.
    :return: Список словарей с индексами и совпадающими символами.
    """
    min_length = min(len(ciphertext1), len(ciphertext2))
    return [
        {"index": i, "char": ciphertext1[i]}
        for i in range(min_length)
        if ciphertext1[i] == ciphertext2[i]
    ]


def find_matching_substrings(ciphertext1, ciphertext2):
    """
    Находит совпадающие подстроки в двух шифротекстах.
    
    :param ciphertext1: Первый шифротекст.
    :param ciphertext2: Второй шифротекст.
    :return: Словарь с совпадающими подстроками и их индексами.
    """
    min_length = min(len(ciphertext1), len(ciphertext2))
    matching_substrings = {}

    for length in range(2, min_length + 1):  # Длина подстрок от 2 до длины текста
        for i in range(min_length - length + 1):
            substring = ciphertext1[i:i + length]
            if substring in ciphertext2:
                if substring not in matching_substrings:
                    matching_substrings[substring] = {
                        "count": 0,
                        "positions_in_ciphertext1": [],
                        "positions_in_ciphertext2": [],
                    }
                matching_substrings[substring]["count"] += 1
                matching_substrings[substring]["positions_in_ciphertext1"].append(i)
                matching_substrings[substring]["positions_in_ciphertext2"].append(
                    ciphertext2.index(substring)
                )
    return matching_substrings


def create_matching_array(ciphertext1, ciphertext2):
    """
    Создаёт массив совпадений, где совпадающие символы остаются, 
    а несовпадающие заменяются на `~`.
    
    :param ciphertext1: Первый шифротекст.
    :param ciphertext2: Второй шифротекст.
    :return: Список символов с совпадениями и заменами.
    """
    min_length = min(len(ciphertext1), len(ciphertext2))
    return [
        ciphertext1[i] if ciphertext1[i] == ciphertext2[i] else "~"
        for i in range(min_length)
    ]


def analyze_encryption(plaintexts, ciphertexts):
    """
    Анализирует шифрование: длины, частоты символов.
    :param plaintexts: Список исходных текстов.
    :param ciphertexts: Список шифротекстов.
    :return: Список словарей с анализом.
    """
    return [
        {
            "plaintext": plaintext,
            "ciphertext": ciphertext,
            "cipher_length": len(ciphertext),
            "plain_length": len(plaintext),
            "cipher_frequencies": Counter(ciphertext),
        }
        for plaintext, ciphertext in zip(plaintexts, ciphertexts)
    ]

def compare_substrings_with_differences(ciphertext1, ciphertext2, substring_length):
    """
    Сравнивает подстроки фиксированной длины между двумя шифротекстами
    и находит индексы различий.

    :param ciphertext1: Первый шифротекст.
    :param ciphertext2: Второй шифротекст.
    :param substring_length: Длина подстроки для сравнения.
    :return: Список объектов с подстрокой и индексами различий.
    """
    n = min(len(ciphertext1), len(ciphertext2))
    result = []

    # Проверяем, что длина подстроки не превышает доступную длину
    if substring_length > n:
        raise ValueError("Длина подстроки превышает длину шифротекста.")

    # Сравниваем подстроки
    for i in range(n - substring_length + 1):
        sub1 = ciphertext1[i:i + substring_length]
        sub2 = ciphertext2[i:i + substring_length]
        differences = [j for j in range(substring_length) if sub1[j] != sub2[j]]
        result.append({
            "substring1": sub1,
            "substring2": sub2,
            "difference_indices": differences
        })

    return result

def extract_blocks_with_noise(ciphertext):
    """
    Разбивает шифротекст на блоки по 16 символов и расставляет шумовые символы (~) по схеме.
    
    Схема: char char ~ char char ~ ~ ~ ~ char ~ char char char ~ ~
    :param ciphertext: Строка шифротекста.
    :return: Список блоков, где символы соответствуют схеме, а шумовые символы заменены на ~.
    """
    # Длина блока
    block_size = 16

    # Схема: True - нужный символ (char), False - шум (~)
    extraction_scheme = [
        True, True, False, True, True, False, False, False,
        False, True, False, True, True, True, False, False
    ]

    # Проверяем, что схема имеет длину 16
    if len(extraction_scheme) != block_size:
        raise ValueError("Схема выделения должна быть длиной 16.")

    # Разбиваем текст на блоки по 16 символов
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # Обрабатываем блоки по схеме
    result = []
    for block in blocks:
        # Если блок неполный, заполняем его пробелами до длины 16
        if len(block) < block_size:
            block = block.ljust(block_size, " ")

        # Применяем схему, заменяя шумовые символы на ~
        processed_block = [
            char if is_char else "~"
            for char, is_char in zip(block, extraction_scheme)
        ]
        result.append(" ".join(processed_block))  # Форматируем блок с пробелами между символами

    return result

def remove_noise_from_blocks(blocks):
    """
    Удаляет символы '~' из блоков, оставляя только нужные символы.
    
    :param blocks: Список строк, содержащих блоки с символами и шумами ('~').
    :return: Список строк, содержащих только нужные символы.
    """
    cleaned_blocks = []
    for block in blocks:
        # Удаляем символы '~' и пробелы, оставляя только значимые символы
        cleaned_block = block.replace("~", "").replace(" ", "")
        cleaned_blocks.append(cleaned_block)
    return cleaned_blocks

def remove_noise_from_ciphertext(ciphertext):
    """
    Удаляет лишние символы из шифротекста по заданной схеме:
    char char ~ char char ~ ~ ~ ~ char ~ char char char ~ ~
    
    :param ciphertext: Строка шифротекста.
    :return: Строка с оставшимися символами.
    """
    # Длина блока
    block_size = 16

    # Схема: True - оставляем символ (char), False - удаляем символ (~)
    extraction_scheme = [
        True, True, False, True, True, False, False, False,
        False, True, False, True, True, True, False, False
    ]

    # Проверяем, что схема имеет длину 16
    if len(extraction_scheme) != block_size:
        raise ValueError("Схема выделения должна быть длиной 16.")

    # Разбиваем текст на блоки по 16 символов
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # Обрабатываем блоки по схеме
    result = []
    for block in blocks:
        # Если блок неполный, игнорируем его
        if len(block) == block_size:
            # Оставляем только те символы, которые соответствуют True в схеме
            filtered_block = [
                char for char, is_char in zip(block, extraction_scheme) if is_char
            ]
            result.append("".join(filtered_block))

    # Объединяем обработанные блоки в одну строку
    return "".join(result)

def pair_characters_from_blocks(ciphertext):
    """
    Разбивает шифртекст на блоки по 8 символов и соединяет символы попарно
    по следующему порядку: (4 и 6), (7 и 5), (8 и 3), (1 и 2).
    
    :param ciphertext: Строка шифротекста без шума.
    :return: Список пар символов.
    """
    # Длина блока
    block_size = 8

    pair_order = [(4, 6), (7, 5), (8, 3), (1, 2)]

    # Разбиваем текст на блоки по 8 символов
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # Обрабатываем каждый блок
    result = []
    for block in blocks:
        # Если блок неполный, пропускаем его
        if len(block) == block_size:
            # Формируем пары по заданному порядку
            pairs = [block[i - 1] + block[j - 1] for i, j in pair_order]
            result.extend(pairs)

    return result

def find_pair_in_array(pairs_array, target_pair):
    """
    Ищет заданную пару символов в массиве из двухсимвольных элементов.
    
    :param pairs_array: Массив строк длиной 2 символа каждая.
    :param target_pair: Пара символов, которую нужно найти.
    :return: Список индексов вхождений пары.
    """
    positions = []

    for index, pair in enumerate(pairs_array):
        if pair == target_pair:
            positions.append(index)

    return positions

def find_most_frequent_chars(array, top_n=None):
    """
    Находит самые частые символы в массиве.
    
    :param array: Массив символов (список строк).
    :param top_n: Количество наиболее частых символов для вывода (если None, выводит все).
    :return: Список кортежей (символ, частота), отсортированный по убыванию частоты.
    """
    # Подсчитываем частоту символов
    counter = Counter(array)
    
    # Сортируем по частоте
    most_frequent = counter.most_common(top_n)
    
    return most_frequent

def replace_syllables_with_letters(syllables, mapping):
    """
    Заменяет английские слоги в массиве на русские буквы по заданному алфавиту.

    :param syllables: Список английских слогов (массив строк).
    :param mapping: Словарь соответствия слогов русским буквам.
    :return: Список русских букв.
    """
    result = []
    for syllable in syllables:
        if syllable in mapping:
            result.append(mapping[syllable])
        else:
            result.append('~')  # Заменяем неизвестный слог на символ '?'
    return result

def arr_in_string(arr):
    return ''.join(arr)

# -------------------------------------------------------------------------------------------------------------------------------------

# print('Анализ символов')
# print(find_repeated_chars(ciphertext2))
# print('Анализ подстрок')
# print(find_repeated_substrings(ciphertext2, 2))
# print('Общий анализ')
# print(analyze_encryption(plaintexts, ciphertexts))

# print('Анализ сравнения на совпадениия двух шифртекстов')
# print('По символам')
# matching_chars = find_matching_chars(ciphertexts[0], ciphertexts[1])
# print(matching_chars)
# print('По подстрокам')
# matching_substrings = find_matching_substrings(ciphertexts[0], ciphertexts[1])
# print(matching_substrings)
# print('Массив с совпадениями')
# matching_array = create_matching_array(ciphertexts[0], ciphertexts[1])
# print(matching_array)

#Шифртекст без шума
ciphertext_without_noise = remove_noise_from_ciphertext(ciphertext1)
#Шифртекст по блокам
normalized_ciphertext_arr = pair_characters_from_blocks(ciphertext_without_noise)

alphabet_mapping = {
    'HF': 'в',
    'NA': 'а',
    'CK': 'х',
    'OI': 'и',
    'KC': 'ч',
    'FG': 'т',
    'NO': 'к',
    'KI': 'о',
    'FA': 'з',
    'CD': '1',
    'AA': ' '
}

result_text = arr_in_string(replace_syllables_with_letters(normalized_ciphertext_arr, alphabet_mapping))
print(result_text)