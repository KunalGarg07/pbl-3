# Deliberately vulnerable demo: evaluates text typed by the user.
user_input = input("Enter expression: ")
result = eval(user_input)
print(result)
