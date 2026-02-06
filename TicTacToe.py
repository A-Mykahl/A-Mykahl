"""
Tic-Tac-Toe with an Unbeatable AI
Play against a computer opponent that uses the Minimax algorithm.
You'll never win — but can you force a draw?
"""

import random


def create_board():
    """Return an empty 3x3 board as a list of 9 spaces."""
    return [" "] * 9


def display_board(board):
    """Print the board with row/column guides."""
    print()
    for row in range(3):
        cells = []
        for col in range(3):
            mark = board[row * 3 + col]
            if mark == " ":
                # show position number as a hint
                cells.append(f" {row * 3 + col + 1} ")
            else:
                cells.append(f" {mark} ")
        print(" | ".join(cells))
        if row < 2:
            print("----+-----+----")
    print()


def check_winner(board, player):
    """Return True if the given player has three in a row."""
    wins = [
        (0, 1, 2), (3, 4, 5), (6, 7, 8),  # rows
        (0, 3, 6), (1, 4, 7), (2, 5, 8),  # columns
        (0, 4, 8), (2, 4, 6),              # diagonals
    ]
    return any(board[a] == board[b] == board[c] == player for a, b, c in wins)


def available_moves(board):
    """Return a list of indexes that are still open."""
    return [i for i, spot in enumerate(board) if spot == " "]


def is_full(board):
    """Return True if no empty spaces remain."""
    return " " not in board


def minimax(board, is_maximizing):
    """
    Minimax algorithm — the AI explores every possible future move
    and picks the path that maximises its own score while minimising yours.

    Returns a score: +1 if AI wins, -1 if human wins, 0 for a draw.
    """
    if check_winner(board, "O"):   # AI wins
        return 1
    if check_winner(board, "X"):   # Human wins
        return -1
    if is_full(board):
        return 0

    if is_maximizing:
        best = -100
        for move in available_moves(board):
            board[move] = "O"
            score = minimax(board, False)
            board[move] = " "
            best = max(best, score)
        return best
    else:
        best = 100
        for move in available_moves(board):
            board[move] = "X"
            score = minimax(board, True)
            board[move] = " "
            best = min(best, score)
        return best


def ai_move(board):
    """Choose the best move for the AI using minimax."""
    best_score = -100
    best_moves = []

    for move in available_moves(board):
        board[move] = "O"
        score = minimax(board, False)
        board[move] = " "
        if score > best_score:
            best_score = score
            best_moves = [move]
        elif score == best_score:
            best_moves.append(move)

    # pick randomly among equally-good moves for variety
    return random.choice(best_moves)


def human_turn(board):
    """Prompt the human player to pick a square."""
    while True:
        try:
            choice = int(input("Your move (1-9): ")) - 1
            if choice < 0 or choice > 8:
                print("Pick a number between 1 and 9.")
            elif board[choice] != " ":
                print("That spot is taken. Try another.")
            else:
                board[choice] = "X"
                return
        except ValueError:
            print("Enter a number between 1 and 9.")


def play():
    """Main game loop."""
    print("=" * 35)
    print("   TIC-TAC-TOE  vs.  UNBEATABLE AI")
    print("=" * 35)
    print("You are X.  The AI is O.")
    print("Pick a square by entering 1-9.")

    board = create_board()
    display_board(board)

    # randomly decide who goes first
    human_first = random.choice([True, False])
    if human_first:
        print("You go first!")
    else:
        print("AI goes first!")
        move = random.choice(available_moves(board))  # random opening for variety
        board[move] = "O"
        print(f"AI plays square {move + 1}.")
        display_board(board)

    while True:
        # --- Human turn ---
        human_turn(board)
        display_board(board)

        if check_winner(board, "X"):
            print("You win! (Wait, that shouldn't happen...)")
            break
        if is_full(board):
            print("It's a draw! Well played.")
            break

        # --- AI turn ---
        print("AI is thinking...")
        move = ai_move(board)
        board[move] = "O"
        print(f"AI plays square {move + 1}.")
        display_board(board)

        if check_winner(board, "O"):
            print("AI wins! Better luck next time.")
            break
        if is_full(board):
            print("It's a draw! Well played.")
            break


if __name__ == "__main__":
    play()

    while input("\nPlay again? (y/n): ").lower().startswith("y"):
        play()

    print("Thanks for playing!")
