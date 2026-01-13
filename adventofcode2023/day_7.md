
# Day 7

## Part 1

Ok, so just get the scores from each game. The puzzle can be split into two parts: sorting the hands by the value of each hand, and getting the score from each game.

So the objective is to sort the hands by their value. One way to encode the value, is to multiply the "type" of each hand by (10**len(cards)) and then add to that the values of each card.

Let me show by example:

Let's say we have a hand: `32T3K` our hypothetical function to get the type would return 1, so multiply `10**5` by one which equals `100000`, now the first card in the hand is `3`, so multiply `10**4` by three.

Now the integer value will be: `130000` . The next number is a two, so `132000` and then the next card is a `T`, so now we should lookup this table: `A, K, Q, J, T, 9, 8, 7, 6, 5, 4, 3, 2` for it. Except uh oh. Yeah we can't represent hands as integers because then we have the `A` cards and such which are more or equal to ten, so it will jumble our encoding, except we can just instead of adding to an integer, we can add to a list, so I think we are still good. This of course adds plenty of overhead, but I don't really care. Another option is to use two integer digits for each hand, but I am going to go with lists.

Actually implementing the hands as integers isn't that bad of an idea. See, if we encode the hands as integers like instead of doing `10**(cardindex)`, I think we should encode it as `len(cards)**(cardindex)`, I think encoding that way, we do not change the order by encoding them.

Let's give it a try. Here is my current code:

{% raw %}
```

import sys


def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	out = []
	for line in lines:
		hand, bid = line.split(" ")
		bid = int(bid)
		out.append([hand, bid])
	print(out)
	return out


def get_hand_type(hand: str) -> int:
	# first 

def get_hand_value(hand: str) -> int:
	# Ok so now just get the type and the hand value.
	hand_type = get_hand_type(hand: str)

def get_bids(cards_and_bids: list) -> int:
	# This actually calculates the score.

	# First sort the list by the value of the hand

	return 0

def main() -> int:
	cards_and_bids = parse_input()

	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

The hardest part of this challenge is to check the type of a hand efficiently. I could make a dictionary which is basically a counter for each card, or even a list could do. Also I think we can calculate the value of the hand at the same time.

Here was my initial attempt:

{% raw %}
```

import sys
from functools import cmp_to_key

def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	out = []
	for line in lines:
		hand, bid = line.split(" ")
		bid = int(bid)
		out.append([hand, bid])
	print(out)
	return out


def get_hand_type(card_counts: dict) -> int:
	'''
	Five of a kind, where all five cards have the same label: AAAAA
	Four of a kind, where four cards have the same label and one card has a different label: AA8AA
	Full house, where three cards have the same label, and the remaining two cards share a different label: 23332
	Three of a kind, where three cards have the same label, and the remaining two cards are each different from any other card in the hand: TTT98
	Two pair, where two cards share one label, two other cards share a second label, and the remaining card has a third label: 23432
	One pair, where two cards share one label, and the other three cards have a different label from the pair and each other: A23A4
	High card, where all cards' labels are distinct: 23456
	'''
	counts = list(card_counts.values())
	pairs = counts.count(2)
	if 5 in counts:
		return 6
	elif 4 in counts:
		return 5
	elif 3 in counts and 2 in counts:
		# Full house
		return 4
	elif 3 in counts:
		return 3
	elif pairs == 2:
		# Two pair
		return 2
	elif pairs == 1:
		# One pair
		return 1
	else:
		return 0 # High card


def get_hand_value(hand: str) -> int:
	# Ok so now just get the type and the hand value.
	#cards = "AKQJT98765432"
	cards = "23456789TJQKA"
	card_values = {cards[i]:i for i in range(len(cards))} # These are the relative values of each card
	card_counts = {str(x): 0 for x in cards}
	out = 0
	for i, card in enumerate(hand):
		card_counts[card] += 1 # This is later used to get the "type" of the hand.
		# Add to the out integer the value of the current card.
		# len(cards)**(cardindex)
		out += (len(cards) - i)**(card_values[card])
	# Now add the type which trumps all other values of the card
	hand_type = get_hand_type(card_counts)
	out += (len(cards)+1)**(hand_type)
	return out


def compare(item1, item2):
	return (item1[1]) - (item2[1])

def get_result(cards_and_bids: list) -> int:
	# This actually calculates the score.

	# First sort the list by the value of the hand
	stuff = []
	for hand, bid in cards_and_bids:
		val = get_hand_value(hand)
		print(str(hand)+": "+str(val))
		stuff.append([hand, val])
	thing = sorted(stuff, key=cmp_to_key(compare))
	print(thing)
	return 0

def main() -> int:
	cards_and_bids = parse_input()
	result = get_result(cards_and_bids)
	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

I think my logic when encoding the values of the cards is flawed, let's debug. Ok after some debugging, I made this modification:
{% raw %}
```
out += (len(cards)+1)**(hand_type+len(cards))
```
{% endraw %}
and now it alteast works for the toy input, but it doesn't work for the main input.


{% raw %}
```


import sys
from functools import cmp_to_key

def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	out = []
	for line in lines:
		hand, bid = line.split(" ")
		bid = int(bid)
		out.append([hand, bid])
	print(out)
	return out


def get_hand_type(card_counts: dict) -> int:
	'''
	Five of a kind, where all five cards have the same label: AAAAA
	Four of a kind, where four cards have the same label and one card has a different label: AA8AA
	Full house, where three cards have the same label, and the remaining two cards share a different label: 23332
	Three of a kind, where three cards have the same label, and the remaining two cards are each different from any other card in the hand: TTT98
	Two pair, where two cards share one label, two other cards share a second label, and the remaining card has a third label: 23432
	One pair, where two cards share one label, and the other three cards have a different label from the pair and each other: A23A4
	High card, where all cards' labels are distinct: 23456
	'''
	counts = list(card_counts.values())
	pairs = counts.count(2)
	if 5 in counts:
		return 6
	elif 4 in counts:
		return 5
	elif 3 in counts and 2 in counts:
		# Full house
		return 4
	elif 3 in counts:
		return 3
	elif pairs == 2:
		# Two pair
		return 2
	elif pairs == 1:
		# One pair
		return 1
	else:
		return 0 # High card


def get_hand_value(hand: str) -> int:
	# Ok so now just get the type and the hand value.
	#cards = "AKQJT98765432"
	cards = "23456789TJQKA"
	card_values = {cards[i]:i for i in range(len(cards))} # These are the relative values of each card
	card_counts = {str(x): 0 for x in cards}
	out = 0
	for i, card in enumerate(hand):
		card_counts[card] += 1 # This is later used to get the "type" of the hand.
		# Add to the out integer the value of the current card.
		# len(cards)**(cardindex)
		out += (len(cards) - i)**(card_values[card])
	# Now add the type which trumps all other values of the card
	hand_type = get_hand_type(card_counts)
	print("Hand type for hand "+str(hand)+" is "+str(hand_type))
	#stuff = (len(cards)+1)**(hand_type+len(cards))
	#print("Adding stuff: "+str(stuff))
	out += (len(cards)+1)**(hand_type+len(cards))
	return out#, hand_type


def compare(item1, item2):
	return item1[0] - item2[0]

def get_result(cards_and_bids: list) -> int:
	# This actually calculates the score.

	# First sort the list by the value of the hand
	stuff = []
	for hand, bid in cards_and_bids:
		val = get_hand_value(hand)
		#print(str(hand)+": "+str(val))
		stuff.append([val, bid, hand])
	thing = sorted(stuff, key=cmp_to_key(compare))
	#print(thing)
	print("Sorted by rank:"+str(stuff))
	print("Now printing all of the hands in order of importance: ")
	for oof in thing:
		print(oof[2])
	total = 0
	count = 1
	for oof in thing:
		total += count*oof[1]
		count += 1
	return total

def main() -> int:
	cards_and_bids = parse_input()
	result = get_result(cards_and_bids)
	print("Result: "+str(result))
	return 0

if __name__=="__main__":
	exit(main())


```
{% endraw %}

I think because the way it calculates the importance of each hand is flawed in some way.

Let's add a sanity test function, which checks the sorted list.

And as it turns out my method was shit!

{% raw %}
```
Now checking: [793714797816966, 497, '87923'] and [793714809100773, 256, '49632']
```
{% endraw %}

so my code says that `49632` is higher than `87923`. Yeah, my logic was flawed. Let's just first sort the list by the type and then sort the hands of same type in their own section.

I refactored my code to this:

{% raw %}
```

import sys
from functools import cmp_to_key

def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	out = []
	for line in lines:
		hand, bid = line.split(" ")
		bid = int(bid)
		out.append([hand, bid])
	print(out)
	return out


def get_hand_type(card_counts: dict) -> int:
	'''
	Five of a kind, where all five cards have the same label: AAAAA
	Four of a kind, where four cards have the same label and one card has a different label: AA8AA
	Full house, where three cards have the same label, and the remaining two cards share a different label: 23332
	Three of a kind, where three cards have the same label, and the remaining two cards are each different from any other card in the hand: TTT98
	Two pair, where two cards share one label, two other cards share a second label, and the remaining card has a third label: 23432
	One pair, where two cards share one label, and the other three cards have a different label from the pair and each other: A23A4
	High card, where all cards' labels are distinct: 23456
	'''
	counts = list(card_counts.values())
	pairs = counts.count(2)
	if 5 in counts:
		return 6
	elif 4 in counts:
		return 5
	elif 3 in counts and 2 in counts:
		# Full house
		return 4
	elif 3 in counts:
		return 3
	elif pairs == 2:
		# Two pair
		return 2
	elif pairs == 1:
		# One pair
		return 1
	else:
		return 0 # High card

# Thanks to https://stackoverflow.com/a/57003713

def compare_hands(item1, item2):
	cards = "23456789TJQKA"
	cards_values = {cards[i]:i for i in range(len(cards))}
	for i in range(len(item1)):
		# Note the way we are sorting here. We are sorting in reverse order (first the worst hand and then the best)
		if cards_values[item1[0][i]] < cards_values[item2[0][i]]:
			return -1 # "return a negative value (< 0) when the left item should be sorted before the right item"
		elif cards_values[item1[0][i]] > cards_values[item2[0][i]]:
			return 1
	# Hands are identical.

	return 0 # "return 0 when both the left and the right item have the same weight and should be ordered "equally" without precedence"

def sort_hands(hands_groups: list) -> None:
	for i in range(len(hands_groups)):
		# Sort each type individially.
		hands_groups[i] = sorted(hands_groups[i], key=cmp_to_key(compare_hands))
	return hands_groups

def get_result(cards_and_bids: list) -> int:
	# This actually calculates the score.
	NUM_OF_TYPES = 7
	# First sort the hands by type.
	#cards = "AKQJT98765432"
	cards = "23456789TJQKA"
	hands_sorted_by_type = [[] for _ in range(NUM_OF_TYPES)]
	for hand, bid in cards_and_bids:
		card_counts = {cards[i]:0 for i in range(len(cards))}
		#print(card_counts)
		for char in hand:
			card_counts[char] += 1
		hand_type = get_hand_type(card_counts)
		hands_sorted_by_type[hand_type].append([hand, bid])
	# Now we have the hands sorted by type. Now sort each of these groups by themselves by the score.
	sort_hands(hands_sorted_by_type)
	# Now they should all be sorted by type and each type group is sorted by value.
	# Join everything together
	all_hands_sorted = [item for row in hands_sorted_by_type for item in row] # Thanks to https://realpython.com/python-flatten-list/
	print("All hands sorted: "+str(all_hands_sorted))
	# Now get the score:
	res = 0
	for i, hand in enumerate(all_hands_sorted):
		res += (i+1)*hand[1] # hand[1] is the bid
	return res

def main() -> int:
	cards_and_bids = parse_input()
	result = get_result(cards_and_bids)
	print("Result: "+str(result))
	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

And it works for the toy input, but it doesn't work for the actual input for some odd reason.

After a couple of fixes I now have this:

{% raw %}
```

import sys
from functools import cmp_to_key

def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	out = []
	for line in lines:
		hand, bid = line.split(" ")
		bid = int(bid)
		out.append([hand, bid])
	print(out)
	return out


def get_hand_type(card_counts: dict) -> int:
	'''
	Five of a kind, where all five cards have the same label: AAAAA
	Four of a kind, where four cards have the same label and one card has a different label: AA8AA
	Full house, where three cards have the same label, and the remaining two cards share a different label: 23332
	Three of a kind, where three cards have the same label, and the remaining two cards are each different from any other card in the hand: TTT98
	Two pair, where two cards share one label, two other cards share a second label, and the remaining card has a third label: 23432
	One pair, where two cards share one label, and the other three cards have a different label from the pair and each other: A23A4
	High card, where all cards' labels are distinct: 23456
	'''
	counts = list(card_counts.values())
	pairs = counts.count(2)
	if 5 in counts:
		return 6
	elif 4 in counts:
		return 5
	elif 3 in counts and 2 in counts:
		# Full house
		return 4
	elif 3 in counts:
		return 3
	elif pairs == 2:
		# Two pair
		return 2
	elif pairs == 1:
		# One pair
		return 1
	else:
		return 0 # High card

# Thanks to https://stackoverflow.com/a/57003713

def compare_hands(item1, item2):
	print("item1 == "+str(item1))
	print("item2 == "+str(item2))
	cards = "23456789TJQKA"
	cards_values = {cards[i]:i for i in range(len(cards))}
	for i in range(len(item1[0])):
		# Note the way we are sorting here. We are sorting in reverse order (first the worst hand and then the best)
		if cards_values[item1[0][i]] < cards_values[item2[0][i]]:
			print(str(cards_values[item1[0][i]]) + "<" + str(cards_values[item2[0][i]]))
			return -1 # "return a negative value (< 0) when the left item should be sorted before the right item"
		elif cards_values[item1[0][i]] > cards_values[item2[0][i]]:
			print(str(cards_values[item1[0][i]]) + ">" + str(cards_values[item2[0][i]]))
			return 1
	# Hands are identical.

	return 0 # "return 0 when both the left and the right item have the same weight and should be ordered "equally" without precedence"

def sort_hands(hands_groups: list) -> None:
	for i in range(len(hands_groups)):
		# Sort each type individially.
		hands_groups[i] = sorted(hands_groups[i], key=cmp_to_key(compare_hands))
	return hands_groups

def get_result(cards_and_bids: list) -> int:
	# This actually calculates the score.
	NUM_OF_TYPES = 7
	# First sort the hands by type.
	#cards = "AKQJT98765432"
	cards = "23456789TJQKA"
	hands_sorted_by_type = [[] for _ in range(NUM_OF_TYPES)]
	for hand, bid in cards_and_bids:
		card_counts = {cards[i]:0 for i in range(len(cards))}
		#print(card_counts)
		for char in hand:
			card_counts[char] += 1
		hand_type = get_hand_type(card_counts)
		print("hand_type == "+str(hand_type))
		hands_sorted_by_type[hand_type].append([hand, bid])
	# Now we have the hands sorted by type. Now sort each of these groups by themselves by the score.
	sort_hands(hands_sorted_by_type)
	# Now they should all be sorted by type and each type group is sorted by value.
	# Join everything together
	all_hands_sorted = [item for row in hands_sorted_by_type for item in row] # Thanks to https://realpython.com/python-flatten-list/
	print("All hands sorted: "+str(all_hands_sorted))
	# Now get the score:
	res = 0
	for i, hand in enumerate(all_hands_sorted):
		res += (i+1)*hand[1] # hand[1] is the bid
	# Run the sanity test
	sanity_test(all_hands_sorted)
	return res


def sanity_test(hands_stuff: list) -> None:
	# This is used to test the program that it works properly.
	cards = "23456789TJQKA"
	card_values = {cards[i]:i for i in range(len(cards))}
	for i in range(len(hands_stuff)-1):
		print("Now checking: "+str(hands_stuff[i])+" and "+str(hands_stuff[i+1]))

		card_counts1 = {str(x): 0 for x in cards}
		card_counts2 = {str(x): 0 for x in cards}
		#card_counts[card] += 1
		
		# Compare hands. The second hand is supposed to be of greater value than the first
		
		#first_hand = hands_stuff[i][2]
		#second_hand = hands_stuff[i+1][2]

		first_hand = hands_stuff[i][0]
		second_hand = hands_stuff[i+1][0]

		for char in first_hand:
			card_counts1[char] += 1
		for char in second_hand:
			card_counts2[char] += 1

		# Now check the type of each hand
		assert get_hand_type(card_counts2) >= get_hand_type(card_counts1)
		if get_hand_type(card_counts2) > get_hand_type(card_counts1):
			continue
		# Now check the values of the cards.
		for i in range(len(first_hand)):
			if first_hand[i] == second_hand[i]:
				continue
			else:
				# Now when they differ, the second hand has to have the higher card
				print("second_hand[i] == "+str(second_hand[i]))
				print("first_hand[i] == "+str(first_hand[i]))
				assert card_values[second_hand[i]] > card_values[first_hand[i]]
				break
	return


def main() -> int:
	cards_and_bids = parse_input()
	result = get_result(cards_and_bids)
	print("Result: "+str(result))
	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

and it works with the actual input! Great!

## Part 2

Ok so for part 2 we basically need to figure out what is the best type we can get if we let the "J" card be whatever we want. But for the purposes of determining which hand is better across hands which have the same type, the "J" card will be treated as a "2" card and all the other cards stay in place in the order.

So we basically have to modify this function:

{% raw %}
```
def get_hand_type(card_counts: dict) -> int:
	'''
	Five of a kind, where all five cards have the same label: AAAAA
	Four of a kind, where four cards have the same label and one card has a different label: AA8AA
	Full house, where three cards have the same label, and the remaining two cards share a different label: 23332
	Three of a kind, where three cards have the same label, and the remaining two cards are each different from any other card in the hand: TTT98
	Two pair, where two cards share one label, two other cards share a second label, and the remaining card has a third label: 23432
	One pair, where two cards share one label, and the other three cards have a different label from the pair and each other: A23A4
	High card, where all cards' labels are distinct: 23456
	'''
	counts = list(card_counts.values())
	pairs = counts.count(2)
	if 5 in counts:
		return 6
	elif 4 in counts:
		return 5
	elif 3 in counts and 2 in counts:
		# Full house
		return 4
	elif 3 in counts:
		return 3
	elif pairs == 2:
		# Two pair
		return 2
	elif pairs == 1:
		# One pair
		return 1
	else:
		return 0 # High card
```
{% endraw %}

to get the best hand possible when a joker can be any value card.

The naive way would be to just go through all of the combinations of cards to get the best possible, but that is inefficient. Let's think the logic through before doing anything.

Let's consider all of the possible amounts of jokers, if we have no jokers, then the rules are the same as before.

If we have one joker, and 4 other cards which are the same, then of course the best we can do is that all of the cards are the same, because the joker can be anything, so if we normally would have returned 5, now return 6.

Then the scenario is that there are two jacks. One thing which I realize, is that the best way to convert the jokers to any card we want, is to just convert them to the card, which has the most copies of it in the hand already, aka if we have a three of a kind and some other card and a joker, of course we convert it to the card which makes up the three of a kind, because four same cards is higher than a full house.
Similarly, if we have two pairs, then we can just choose one or the other. Note that the card which we decide the joker is doesn't affect the sorting of hands which have the same type, it only matters when deciding the type of the hand. Otherwise jokers are automatically considered the lowest.

Here is the modified code:

{% raw %}
```

import sys
from functools import cmp_to_key

def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	out = []
	for line in lines:
		hand, bid = line.split(" ")
		bid = int(bid)
		out.append([hand, bid])
	print(out)
	return out


def get_hand_type(card_counts: dict) -> int:
	'''
	Five of a kind, where all five cards have the same label: AAAAA
	Four of a kind, where four cards have the same label and one card has a different label: AA8AA
	Full house, where three cards have the same label, and the remaining two cards share a different label: 23332
	Three of a kind, where three cards have the same label, and the remaining two cards are each different from any other card in the hand: TTT98
	Two pair, where two cards share one label, two other cards share a second label, and the remaining card has a third label: 23432
	One pair, where two cards share one label, and the other three cards have a different label from the pair and each other: A23A4
	High card, where all cards' labels are distinct: 23456
	'''
	
	joker_count = card_counts["J"] # jokers
	card_counts["J"] = 0 # Take the jokers out temporarily
	out = None
	# Add the jokers to the card which already has the most copies. That way we get the best hand.
	max_copy_card = max(card_counts, key=card_counts.get)
	card_counts[max_copy_card] += joker_count # Transform the jokers to the card which already has most copies.

	counts = list(card_counts.values())

	pairs = counts.count(2)
	if 5 in counts:
		out = 6
	elif 4 in counts:
		out = 5
	elif 3 in counts and 2 in counts:
		# Full house
		out = 4
	elif 3 in counts:
		out = 3
	elif pairs == 2:
		# Two pair
		out = 2
	elif pairs == 1:
		# One pair
		out = 1
	else:
		out = 0 # High card

	return out

# Thanks to https://stackoverflow.com/a/57003713

def compare_hands(item1, item2):
	print("item1 == "+str(item1))
	print("item2 == "+str(item2))
	cards = "J23456789TQKA"
	cards_values = {cards[i]:i for i in range(len(cards))}
	for i in range(len(item1[0])):
		# Note the way we are sorting here. We are sorting in reverse order (first the worst hand and then the best)
		if cards_values[item1[0][i]] < cards_values[item2[0][i]]:
			print(str(cards_values[item1[0][i]]) + "<" + str(cards_values[item2[0][i]]))
			return -1 # "return a negative value (< 0) when the left item should be sorted before the right item"
		elif cards_values[item1[0][i]] > cards_values[item2[0][i]]:
			print(str(cards_values[item1[0][i]]) + ">" + str(cards_values[item2[0][i]]))
			return 1
	# Hands are identical.

	return 0 # "return 0 when both the left and the right item have the same weight and should be ordered "equally" without precedence"

def sort_hands(hands_groups: list) -> None:
	for i in range(len(hands_groups)):
		# Sort each type individially.
		hands_groups[i] = sorted(hands_groups[i], key=cmp_to_key(compare_hands))
	return hands_groups

def get_result(cards_and_bids: list) -> int:
	# This actually calculates the score.
	NUM_OF_TYPES = 7
	# First sort the hands by type.
	#cards = "AKQJT98765432"
	cards = "J23456789TQKA"
	hands_sorted_by_type = [[] for _ in range(NUM_OF_TYPES)]
	for hand, bid in cards_and_bids:
		card_counts = {cards[i]:0 for i in range(len(cards))}
		#print(card_counts)
		for char in hand:
			card_counts[char] += 1
		hand_type = get_hand_type(card_counts)
		print("hand_type == "+str(hand_type))
		hands_sorted_by_type[hand_type].append([hand, bid])
	# Now we have the hands sorted by type. Now sort each of these groups by themselves by the score.
	sort_hands(hands_sorted_by_type)
	# Now they should all be sorted by type and each type group is sorted by value.
	# Join everything together
	all_hands_sorted = [item for row in hands_sorted_by_type for item in row] # Thanks to https://realpython.com/python-flatten-list/
	print("All hands sorted: "+str(all_hands_sorted))
	# Now get the score:
	res = 0
	for i, hand in enumerate(all_hands_sorted):
		res += (i+1)*hand[1] # hand[1] is the bid
	# Run the sanity test
	#sanity_test(all_hands_sorted)
	return res

def main() -> int:
	cards_and_bids = parse_input()
	result = get_result(cards_and_bids)
	print("Result: "+str(result))
	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

and it works for the actual input. Great!



































