RESET = "\033[0m"       
BOLD = "\033[1m"        
UNDERLINE = "\033[4m"   

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
LIGHT_BLUE = "\033[94m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"

def green(con):
    print(f"{GREEN}"+con+f"{RESET}")

def red(con):
    print(f"{RED}"+con+f"{RESET}")

def yellow(con):
    print(f"{YELLOW}"+con+f"{RESET}")

def light_blue(con):
    print(f"{LIGHT_BLUE}"+con+f"{RESET}")
