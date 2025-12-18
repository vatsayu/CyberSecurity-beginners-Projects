#!/bin/bash
# ============================================
# Typing Master - Word Mode (Clean & Fixed)
# ============================================

# ------------------ COLORS ------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# ------------------ GLOBALS ------------------
score=0
correct=0
total=0
difficulty="medium"
timeout=4
start_time=0
target_word=""
WORDS_FILE="words.txt"
COLUMNS=$(tput cols)

# ------------------ EXIT HANDLER ------------------
graceful_exit() {
    tput sgr0
    tput cnorm
    clear

    acc=0
    (( total > 0 )) && acc=$(( correct * 100 / total ))

    echo -e "${GREEN}🎯 Thanks for playing Typing Master (Word Mode)!${NC}"
    echo "Score    : $score"
    echo "Accuracy : $acc%"
    echo
    exit 0
}

trap graceful_exit INT

# ------------------ UI ------------------
draw_interface() {
    clear

    echo -e "${WHITE}┌$(printf '─%.0s' $(seq 1 $((COLUMNS-2))))┐${NC}"

    title="🎯 TYPING MASTER | WORD MODE | $difficulty 🎯"
    pad=$(( (COLUMNS - ${#title} - 2) / 2 ))
    echo -e "${WHITE}│$(printf '%*s' $pad '')${MAGENTA}${title}${WHITE}$(printf '%*s' $pad '')│${NC}"

    time_elapsed=$(( $(date +%s) - start_time ))
    acc=0
    (( total > 0 )) && acc=$(( correct * 100 / total ))

    printf "${WHITE}│ Time: ${YELLOW}%3ds${WHITE} | Accuracy: ${YELLOW}%3d%%${WHITE} | Score: ${GREEN}%5d${WHITE}%*s│${NC}\n" \
        "$time_elapsed" "$acc" "$score" "$((COLUMNS-60))" ""

    echo -e "${WHITE}├$(printf '─%.0s' $(seq 1 $((COLUMNS-2))))┤${NC}"

    for ((i=0; i<10; i++)); do
        echo -e "${WHITE}│$(printf '%*s' $((COLUMNS-2)) '')│${NC}"
    done

    echo -e "${WHITE}├$(printf '─%.0s' $(seq 1 $((COLUMNS-2))))┤${NC}"
    echo -e "${WHITE}│ Type the word and press Enter (Ctrl+C to exit)$(printf '%*s' $((COLUMNS-49)) '')│${NC}"
    echo -e "${WHITE}└$(printf '─%.0s' $(seq 1 $((COLUMNS-2))))┘${NC}"
}

# ------------------ MENUS ------------------
welcome_screen() {
    clear
    echo -e "${MAGENTA}"
    cat << "EOF"
████████╗██╗   ██╗██████╗ ██╗███╗   ██╗ ██████╗ 
╚══██╔══╝╚██╗ ██╔╝██╔══██╗██║████╗  ██║██╔════╝ 
   ██║    ╚████╔╝ ██████╔╝██║██╔██╗ ██║██║  ███╗
   ██║     ╚██╔╝  ██╔═══╝ ██║██║╚██╗██║██║   ██║
   ██║      ██║   ██║     ██║██║ ╚████║╚██████╔╝
   ╚═╝      ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
EOF
    echo -e "${YELLOW}🎯 Welcome to Typing Master (Word Mode) 🎯${NC}"
    echo "Press Enter to continue..."
    read -r
}

select_difficulty() {
    clear
    echo -e "${CYAN}Select Difficulty${NC}"
    echo "1) Easy   (6s per word)"
    echo "2) Medium (4s)"
    echo "3) Hard   (2s)"
    read -p "Choice: " c

    case "$c" in
        1) difficulty="easy"; timeout=6 ;;
        3) difficulty="hard"; timeout=2 ;;
        *) difficulty="medium"; timeout=4 ;;
    esac
}

# ------------------ WORD LOGIC ------------------
load_words() {
    if [[ ! -f "$WORDS_FILE" ]]; then
        echo "word.txt not found!"
        exit 1
    fi
    mapfile -t WORDS < "$WORDS_FILE"
}

generate_word() {
    echo "${WORDS[RANDOM % ${#WORDS[@]}]}"
}

# ------------------ MAIN ------------------
welcome_screen
select_difficulty
load_words

start_time=$(date +%s)
target_word=$(generate_word)

tput civis

while true; do
    draw_interface

    row=9
    col=$(( (COLUMNS - ${#target_word}) / 2 ))

    tput cup $row $col
    echo -ne "${YELLOW}${target_word}${NC}"

    tput cup $((row+2)) $((col-5))
    echo -ne "${CYAN}Your input: ${NC}"
    tput cnorm

    if read -t "$timeout" user_input; then
        ((total++))
        tput civis

        if [[ "$user_input" == "$target_word" ]]; then
            ((correct++))
            ((score += 15))
            tput cup $((row+4)) $((col-4))
            echo -ne "${GREEN}✔ CORRECT${NC}"
        else
            ((score -= 5))
            ((score < 0)) && score=0
            tput cup $((row+4)) $((col-4))
            echo -ne "${RED}✘ WRONG${NC}"
        fi
    else
        tput civis
        tput cup $((row+4)) $((col-6))
        echo -ne "${RED}⏱ TIMEOUT${NC}"
    fi

    sleep 1
    target_word=$(generate_word)
done
