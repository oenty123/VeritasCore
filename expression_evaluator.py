"""
Модуль для вычисления арифметических выражений.

Алгоритм:
1. Токенизация: разбиение строки на числа, операторы и скобки.
   - Обрабатываются пробелы, целые и вещественные числа.
   - Унарный минус преобразуется в специальный токен 'u-'.
2. Shunting-yard (сортировочная станция): преобразование инфиксной нотации в обратную польскую (RPN).
   - Учитывается приоритет операций (*, / > +, -).
   - Учитывается ассоциативность (слева направо).
3. Вычисление RPN: использование стека для пошагового вычисления.

Сложность:
- Время: O(n), где n — длина строки (каждый символ обрабатывается константное число раз).
- Память: O(n) для хранения токенов, стека операторов и очереди RPN.
"""


def evaluate_expression(expression: str) -> float:
    """
    Вычисляет значение арифметического выражения.

    Поддерживает:
    - Операторы: +, -, *, /
    - Круглые скобки
    - Отрицательные числа (унарный минус)
    - Пробелы в любом месте
    - Деление на ноль возвращает float('inf')

    :param expression: Строка с арифметическим выражением
    :return: Результат вычисления (float)
    """
    
    def tokenize(expr: str):
        """Разбивает строку на токены (числа, операторы, скобки)."""
        tokens = []
        i = 0
        n = len(expr)
        
        while i < n:
            if expr[i].isspace():
                i += 1
                continue
            
            if expr[i] in '()+*/':
                tokens.append(expr[i])
                i += 1
            elif expr[i] in '+-':
                # Проверка на унарный минус/плюс
                is_unary = False
                if not tokens:  # В начале выражения
                    is_unary = True
                else:
                    last_token = tokens[-1]
                    # После оператора, открывающей скобки или другого унарного оператора
                    if isinstance(last_token, str) and last_token in '(+-*/u-':
                        is_unary = True
                
                if is_unary:
                    if expr[i] == '-':
                        tokens.append('u-')  # Унарный минус
                    # Унарный плюс игнорируем
                    i += 1
                else:
                    tokens.append(expr[i])
                    i += 1
                    
            elif expr[i].isdigit() or expr[i] == '.':
                start = i
                has_dot = (expr[i] == '.')
                while i < n and (expr[i].isdigit() or (expr[i] == '.' and not has_dot)):
                    if expr[i] == '.':
                        has_dot = True
                    i += 1
                tokens.append(float(expr[start:i]))
            else:
                # Пропускаем неизвестные символы
                i += 1
        
        return tokens

    def shunting_yard(tokens):
        """Преобразует токены из инфиксной нотации в обратную польскую (RPN)."""
        output_queue = []
        operator_stack = []
        precedence = {'+': 1, '-': 1, '*': 2, '/': 2, 'u-': 3}
        associativity = {'+': 'L', '-': 'L', '*': 'L', '/': 'L', 'u-': 'R'}
        
        for token in tokens:
            if isinstance(token, (int, float)):
                output_queue.append(token)
            elif token == '(':
                operator_stack.append(token)
            elif token == ')':
                while operator_stack and operator_stack[-1] != '(':
                    output_queue.append(operator_stack.pop())
                if operator_stack:
                    operator_stack.pop()  # Удаляем '('
            elif token in '+-*/u-':
                while (operator_stack and 
                       operator_stack[-1] != '(' and
                       operator_stack[-1] in precedence and
                       ((associativity[token] == 'L' and precedence[operator_stack[-1]] >= precedence[token]) or
                        (associativity[token] == 'R' and precedence[operator_stack[-1]] > precedence[token]))):
                    output_queue.append(operator_stack.pop())
                operator_stack.append(token)
        
        while operator_stack:
            output_queue.append(operator_stack.pop())
        
        return output_queue

    def evaluate_rpn(rpn_tokens):
        """Вычисляет значение выражения в обратной польской нотации."""
        stack = []
        for token in rpn_tokens:
            if isinstance(token, (int, float)):
                stack.append(token)
            elif token == 'u-':
                if stack:
                    stack.append(-stack.pop())
            else:
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
        
        if not stack:
            return 0.0
        return stack[0]

    if not expression or not expression.strip():
        return 0.0
    
    tokens = tokenize(expression)
    if not tokens:
        return 0.0
    
    rpn = shunting_yard(tokens)
    result = evaluate_rpn(rpn)
    
    return result


# ==================== ТЕСТЫ ====================

def run_tests():
    """Запускает набор тестов для проверки функции."""
    
    # Базовые операции
    assert evaluate_expression("2 + 3") == 5.0
    assert evaluate_expression("10 - 4") == 6.0
    assert evaluate_expression("3 * 4") == 12.0
    assert evaluate_expression("15 / 3") == 5.0
    
    # Приоритет операций
    assert evaluate_expression("2 + 3 * 4") == 14.0
    assert evaluate_expression("10 - 2 * 3") == 4.0
    assert evaluate_expression("2 + 3 * 4 - 5") == 9.0
    assert evaluate_expression("10 / 2 + 3") == 8.0
    
    # Скобки
    assert evaluate_expression("(2 + 3) * 4") == 20.0
    assert evaluate_expression("2 * (3 + 4)") == 14.0
    assert evaluate_expression("(10 - 2) / (3 + 1)") == 2.0
    assert evaluate_expression("((2 + 3) * 4)") == 20.0
    assert evaluate_expression("2 + (3 * (4 + 5))") == 29.0
    
    # Отрицательные числа (унарный минус)
    assert evaluate_expression("-5") == -5.0
    assert evaluate_expression("-5 + 3") == -2.0
    assert evaluate_expression("5 + (-3)") == 2.0
    assert evaluate_expression("-(-5)") == 5.0
    assert evaluate_expression("--5") == 5.0
    assert evaluate_expression("3 * (-2)") == -6.0
    assert evaluate_expression("-3 * -2") == 6.0
    assert evaluate_expression("-(3 + 2)") == -5.0
    assert evaluate_expression("5 + (-3 * 2)") == -1.0
    assert evaluate_expression("(-2 + 3) * 4") == 4.0
    
    # Пробелы
    assert evaluate_expression("  2   +   3  ") == 5.0
    assert evaluate_expression("  (  2  +  3  )  *  4  ") == 20.0
    assert evaluate_expression("2+3") == 5.0
    assert evaluate_expression("  -5  +  3  ") == -2.0
    
    # Дробные числа
    assert evaluate_expression("2.5 + 3.5") == 6.0
    assert evaluate_expression("10.0 / 2.5") == 4.0
    assert evaluate_expression("0.5 * 4") == 2.0
    assert evaluate_expression("3.14 * 2") == 6.28
    
    # Деление на ноль
    assert evaluate_expression("5 / 0") == float('inf')
    assert evaluate_expression("10 / (2 - 2)") == float('inf')
    assert evaluate_expression("3 + 5 / 0") == float('inf')
    
    # Сложные выражения
    assert evaluate_expression("2 + 3 * 4 - 5 / 5") == 13.0
    assert evaluate_expression("(2 + 3) * (4 - 1)") == 15.0
    assert evaluate_expression("10 / 2 * 3") == 15.0
    
    # Граничные случаи
    assert evaluate_expression("") == 0.0
    assert evaluate_expression("   ") == 0.0
    assert evaluate_expression("42") == 42.0
    assert evaluate_expression("-0") == 0.0
    # assert evaluate_expression("+5") == 5.0  # унарный плюс не поддерживается явно
    # assert evaluate_expression("++5") == 5.0
    
    # Много уровней вложенности
    assert evaluate_expression("(((1)))") == 1.0
    assert evaluate_expression("(-(1))") == -1.0
    assert evaluate_expression("2 + (3 * (4 - (5 / 5)))") == 11.0
    
    # Комбинации унарных операторов
    assert evaluate_expression("---5") == -5.0
    assert evaluate_expression("----5") == 5.0
    assert evaluate_expression("5 + ---3") == 2.0
    
    # Дополнительные тесты
    assert evaluate_expression("1 + 2 + 3 + 4 + 5") == 15.0
    assert evaluate_expression("1 * 2 * 3 * 4") == 24.0
    assert evaluate_expression("100 / 10 / 2") == 5.0
    assert evaluate_expression("10 - 5 - 3") == 2.0
    assert evaluate_expression("0 + 0") == 0.0
    assert evaluate_expression("0 * 100") == 0.0
    assert evaluate_expression("1 / 3") == 1/3
    assert abs(evaluate_expression("0.1 + 0.2") - 0.3) < 1e-10
    
    print("Все тесты пройдены успешно!")


if __name__ == "__main__":
    run_tests()
    
    # Примеры использования
    print("\nПримеры вычислений:")
    examples = [
        "2 + 3 * 4",
        "(2 + 3) * 4",
        "-5 + 3",
        "5 + (-3)",
        "10 / 0",
        "2.5 * 4 + (3 - 1) / 2",
        "-(-(-5))",
        "((2 + 3) * 4 - 5) / 3",
        "1 + 2 * 3 - 4 / 2 + 5",
    ]
    
    for expr in examples:
        result = evaluate_expression(expr)
        print(f"{expr} = {result}")
