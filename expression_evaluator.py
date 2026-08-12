"""
Модуль для вычисления арифметических выражений.

Алгоритм:
1. Токенизация: разбиваем строку на числа, операторы и скобки
2. Shunting-yard алгоритм: преобразуем инфиксную нотацию в обратную польскую (RPN)
3. Вычисление RPN: используем стек для вычисления результата

Сложность:
- Время: O(n), где n - длина строки (каждый символ обрабатывается константное число раз)
- Память: O(n) для хранения токенов, стека операторов и RPN

Особенности:
- Поддерживает +, -, *, / и круглые скобки
- Обрабатывает унарный минус (-5, 5+(-3), -(-5))
- Деление на ноль возвращает float('inf')
- Пробелы игнорируются
"""

import re
from typing import List, Union


def evaluate_expression(expression: str) -> float:
    """
    Вычисляет арифметическое выражение из строки.
    
    Args:
        expression: Строка с арифметическим выражением
        
    Returns:
        Результат вычисления как float
        
    Raises:
        ValueError: При некорректном синтаксисе выражения
    """
    if not expression or not expression.strip():
        raise ValueError("Пустое выражение")
    
    tokens = _tokenize(expression)
    if not tokens:
        raise ValueError("Пустое выражение")
    
    rpn = _to_rpn(tokens)
    result = _evaluate_rpn(rpn)
    
    return result


def _tokenize(expression: str) -> List[Union[float, str]]:
    """
    Токенизирует выражение на числа, операторы и скобки.
    
    Возвращает список чисел (float) и строк-операторов ('+', '-', '*', '/', '(', ')').
    """
    tokens = []
    i = 0
    n = len(expression)
    
    while i < n:
        char = expression[i]
        
        # Пропускаем пробелы
        if char.isspace():
            i += 1
            continue
        
        # Число (целое или дробное)
        if char.isdigit() or (char == '.' and i + 1 < n and expression[i + 1].isdigit()):
            j = i
            has_dot = (char == '.')
            while j < n and (expression[j].isdigit() or (expression[j] == '.' and not has_dot)):
                if expression[j] == '.':
                    has_dot = True
                j += 1
            tokens.append(float(expression[i:j]))
            i = j
            continue
        
        # Операторы и скобки
        if char in '+-*/()':
            tokens.append(char)
            i += 1
            continue
        
        # Некорректный символ
        raise ValueError(f"Некорректный символ: {char}")
    
    return tokens


def _to_rpn(tokens: List[Union[float, str]]) -> List[Union[float, str]]:
    """
    Преобразует токены из инфиксной нотации в обратную польскую (RPN).
    
    Использует алгоритм shunting-yard с поддержкой унарного минуса.
    Унарный минус обозначается как 'u-' для различия с бинарным '-'.
    """
    output = []
    op_stack = []
    
    precedence = {'+': 1, '-': 1, '*': 2, '/': 2, 'u-': 3}
    right_associative = {'u-'}
    
    prev_token = None
    
    for token in tokens:
        if isinstance(token, (int, float)):
            output.append(token)
            prev_token = token
        elif token == '(':
            op_stack.append(token)
            prev_token = token
        elif token == ')':
            while op_stack and op_stack[-1] != '(':
                output.append(op_stack.pop())
            if not op_stack:
                raise ValueError("Несбалансированные скобки")
            op_stack.pop()  # Удаляем '('
            prev_token = token
        else:  # Оператор
            # Определяем, является ли '-' унарным
            if token == '-':
                if prev_token is None or prev_token in ('(', '+', '-', '*', '/'):
                    token = 'u-'  # Унарный минус
            
            # Обработка приоритета операторов
            while (op_stack and 
                   op_stack[-1] != '(' and
                   ((token not in right_associative and 
                     precedence.get(token, 0) <= precedence.get(op_stack[-1], 0)) or
                    (token in right_associative and 
                     precedence.get(token, 0) < precedence.get(op_stack[-1], 0)))):
                output.append(op_stack.pop())
            
            op_stack.append(token)
            prev_token = token
    
    # Добавляем оставшиеся операторы
    while op_stack:
        op = op_stack.pop()
        if op == '(':
            raise ValueError("Несбалансированные скобки")
        output.append(op)
    
    return output


def _evaluate_rpn(rpn: List[Union[float, str]]) -> float:
    """
    Вычисляет выражение в обратной польской нотации.
    """
    stack = []
    
    for token in rpn:
        if isinstance(token, (int, float)):
            stack.append(float(token))
        else:
            if len(stack) < 1:
                raise ValueError("Некорректное выражение")
            
            if token == 'u-':
                operand = stack.pop()
                stack.append(-operand)
            elif token in ('+', '-', '*', '/'):
                if len(stack) < 2:
                    raise ValueError("Некорректное выражение")
                b = stack.pop()
                a = stack.pop()
                
                if token == '+':
                    stack.append(a + b)
                elif token == '-':
                    stack.append(a - b)
                elif token == '*':
                    stack.append(a * b)
                elif token == '/':
                    if b == 0:
                        stack.append(float('inf'))
                    else:
                        stack.append(a / b)
            else:
                raise ValueError(f"Неизвестный оператор: {token}")
    
    if len(stack) != 1:
        raise ValueError("Некорректное выражение")
    
    return stack[0]


# Тесты
if __name__ == "__main__":
    # Базовые операции
    assert evaluate_expression("2 + 3") == 5.0
    assert evaluate_expression("10 - 4") == 6.0
    assert evaluate_expression("3 * 4") == 12.0
    assert evaluate_expression("15 / 3") == 5.0
    
    # Приоритет операций
    assert evaluate_expression("2 + 3 * 4") == 14.0
    assert evaluate_expression("(2 + 3) * 4") == 20.0
    assert evaluate_expression("10 - 2 * 3") == 4.0
    assert evaluate_expression("(10 - 2) * 3") == 24.0
    
    # Вложенные скобки
    assert evaluate_expression("((2 + 3) * 4)") == 20.0
    assert evaluate_expression("2 * (3 + (4 * 5))") == 46.0
    assert evaluate_expression("(((1 + 2) * 3) + 4)") == 19.0
    
    # Унарный минус
    assert evaluate_expression("-5") == -5.0
    assert evaluate_expression("5 + (-3)") == 2.0
    assert evaluate_expression("-(-5)") == 5.0
    assert evaluate_expression("5 * (-2)") == -10.0
    assert evaluate_expression("-5 + 3") == -2.0
    assert evaluate_expression("5 + -3") == 2.0
    assert evaluate_expression("-5 + -3") == -8.0
    assert evaluate_expression("(-5) * (-3)") == 15.0
    assert evaluate_expression("-(5 + 3)") == -8.0
    assert evaluate_expression("-2 * -3") == 6.0
    
    # Дробные числа
    assert evaluate_expression("2.5 + 3.5") == 6.0
    assert evaluate_expression("10.5 - 2.5") == 8.0
    assert evaluate_expression("2.5 * 4") == 10.0
    assert evaluate_expression("7.5 / 2.5") == 3.0
    
    # Пробелы
    assert evaluate_expression("  2   +   3  ") == 5.0
    assert evaluate_expression(" ( 2 + 3 ) * 4 ") == 20.0
    assert evaluate_expression("  -5  +  3  ") == -2.0
    
    # Деление на ноль
    assert evaluate_expression("5 / 0") == float('inf')
    assert evaluate_expression("10 / (2 - 2)") == float('inf')
    assert evaluate_expression("5 + 3 / 0") == float('inf')
    
    # Сложные выражения
    assert evaluate_expression("2 + 3 * 4 - 5") == 9.0
    assert evaluate_expression("(2 + 3) * (4 - 1)") == 15.0
    assert evaluate_expression("10 / 2 + 3 * 4") == 17.0
    assert evaluate_expression("-2 + 3 * (-4 + 5)") == 1.0
    assert evaluate_expression("2 * 3 + 4 * 5") == 26.0
    assert evaluate_expression("100 / (2 + 3) * 4") == 80.0
    
    # Граничные случаи
    assert evaluate_expression("42") == 42.0
    assert evaluate_expression("-0") == 0.0
    assert evaluate_expression("0.0") == 0.0
    
    print("Все тесты пройдены успешно! ✓")
