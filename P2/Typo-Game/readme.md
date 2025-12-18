🎯 Typing Master – Bash Typing Game (Word Mode)

A terminal-based typing game written in Bash designed to improve typing speed and accuracy using random words loaded from a file.
This project is beginner-friendly and also useful for Linux, Bash scripting, and SOC fundamentals.

📌 Features

🎨 Colorful terminal UI using ANSI escape codes

🧠 Word-based typing practice

⏱️ Difficulty levels with time limits

📂 Loads words dynamically from word.txt

📊 Real-time score and accuracy tracking

🧮 Accuracy calculation

🛑 Graceful exit using Ctrl + C

🐧 Works on Linux (Kali, Ubuntu, etc.)

📁 Project Structure
typing-master/
├── typing_master_words.sh
├── word.txt
└── README.md

📄 word.txt Example
split
burst
dispose
blast
consume
hello
world
linux
bash
typing
quick
brown
fox
jump
over
lazy
dog
apple
banana
cherry


You can add or remove words freely.

🚀 How to Run
1️⃣ Clone the repository
git clone https://github.com/your-username/typing-master.git
cd typing-master

2️⃣ Give execution permission
chmod +x typing_master_words.sh

3️⃣ Run the game
./typing_master_words.sh

🎮 Gameplay Instructions

Choose a difficulty level

A random word will appear on the screen

Type the word exactly and press Enter

Score increases for correct words

Accuracy is calculated based on correct attempts

Press Ctrl + C anytime to exit gracefully

⚙️ Difficulty Levels
Difficulty	Time per Word
Easy	6 seconds
Medium	4 seconds
Hard	2 seconds
📊 Scoring System

✅ Correct word: +15 points

❌ Wrong word: −5 points

⏱️ Timeout: No score

🔒 Score never goes below zero

🧠 What You Learn From This Project

Bash scripting fundamentals

File handling in Bash (mapfile)

Terminal UI control (tput)

Signal handling (trap)

Time-based input handling

Clean code structuring

Linux terminal automation

🛡️ SOC / Cybersecurity Relevance

This project helps build skills useful in:

Linux system interaction

Bash automation

Terminal monitoring tools

Event-based input handling

Script-based tools used in SOC environments

🧪 Tested On

✅ Kali Linux

✅ Ubuntu

✅ Bash 5+

🔮 Future Improvements

⌨️ Words Per Minute (WPM)

🗂️ Session logging

📈 Leaderboard system

🧠 Mixed mode (characters + words)

🧪 Debug / training mode

📜 License

This project is open-source and free to use for learning and educational purposes.

👤 Author

Ayush Vats
Beginner Cybersecurity | SOC | Bash Scripting
GitHub: https://github.com/vatsayu-/