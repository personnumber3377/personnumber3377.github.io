
# Day 4

## Part 1

Basically just get the scores from each scratchcard. Because the winning numbers and the scratchcard numbers do not have duplicates, we can use sets instead of lists.

This was my first attempt:

{% raw %}
```


import sys

def parse_input() -> list:
	# Get the scratchcards. (the numbers on the left of "|" are the winning numbers)
	stdin_input_lines = sys.stdin.read().split("\n")
	out = []
	for line in stdin_input_lines:
		numbers = line[line.index(":")+2:]
		#winning_numbers, our_numbers = [(int(y) if y != "" for y in x.split(" ")) for x in numbers.split("|")]
		
		winning_stuff, our_numbers_stuff = numbers.split("|")

		#print(list(winning_stuff))
		#print(list(our_numbers_stuff))
		winning_numbers = winning_stuff[:-1].split(" ")
		our_numbers = our_numbers_stuff[1:].split(" ")
		#print(winning_numbers)
		#print(our_numbers)
		our_numbers = set(our_numbers)

		out.append([winning_numbers, our_numbers])

	return out

def solve(scratchcards: list) -> int:
	# Now get the winning amounts of numbers for each line.
	
	tot_score = 0
	print("scratchcards == "+str(scratchcards))
	for winning_numbers, actual_numbers in scratchcards:
		power = 0
		# Now just get how many of the winning numbers are in the actual_numbers and that is the score basically.
		for num in winning_numbers:
			if num in actual_numbers:
				power += 1
				print("num == "+str(num))
		if power != 0:
			score = 2**(power-1)
			print("score == "+str(score))
			tot_score += score
	return tot_score

def main() -> int:
	scratchcards = parse_input()
	result = solve(scratchcards)
	print(result)
	return 0

if __name__=="__main__":
	exit(main())


```
{% endraw %}

and it doesn't work. This is because when parsing the input, not all of the numbers are of the same length. Therefore when we ".split()" those strings, we are going to have empty strings. After adding a check for an empty string:


{% raw %}
```
		for num in winning_numbers:
			if num == "":
				continue
```
{% endraw %}

the code works.

# Part 2

Ok so now instead of counting the scores of each scratchcard, now get the scores of each scratchcard and then get the scores of those next cards and so on. I think the best way to do this is to do memoization. Because the results of a scratchcard doesn't change, so if we go over a scratchcard again later, we can look up the value of that certain scratchcard later, so we not need compute it again.

Here was my attempt at that:

{% raw %}
```

def get_winning_numbers_amount(scratchcards: list, cur_index: int):
	power = 0
	#print("scratchcards == "+str(scratchcards))
	#print("scratchcards[cur_index] == "+str(scratchcards[cur_index]))
	#for winning_numbers, actual_numbers in scratchcards[cur_index]:
	winning_numbers, actual_numbers = scratchcards[cur_index]
	#power = 0
	# Now just get how many of the winning numbers are in the actual_numbers and that is the score basically.
	for num in winning_numbers:
		if num == "":
			continue
		if num in actual_numbers:
			power += 1
			#print("num == "+str(num))
		
	return power

def check_scratchcard_recursive(scratchcards: list, cur_index: int, already_computed: dict) -> int: # Returns the amount of subsequent scratchcards
	if cur_index in already_computed: # We have already calculated how many scratchcards there are for this specific specific scratchcard
		return already_computed[cur_index]
	tot_scratch_cards = 0 # These are the total scratch cards processed.
	next_scratchcard_count = get_winning_numbers_amount(scratchcards, cur_index)
	tot_scratch_cards += 1 # We scratched one scratchcard.
	for i in range(1, next_scratchcard_count+1): # Go through the next winning amount number of scratchcards recursively.
		tot_scratch_cards += check_scratchcard_recursive(scratchcards, cur_index + i, already_computed)
	already_computed[cur_index] = tot_scratch_cards # This is used to prevent computing the same scratchcards over and over again, when we have already computed them
	return tot_scratch_cards

def solve_part_2(scratchcards: list) -> int:
	# These are the already-computed scratchcards, such that we do not need to compute them again.
	already_computed = dict() # the scratchcard number is the key and the value is the amount of subsequent scratchcards.
	all_scratch_cards_amount = 0
	for i, scratchcard in enumerate(scratchcards):
		all_scratch_cards_amount += check_scratchcard_recursive(scratchcards, i, already_computed)
	return all_scratch_cards_amount

```
{% endraw %}

and it works for the toy input. Does it work for the actual input? Yes! I think I should explain how this code works. When going over the scratchcards, you will encounter the same scratchcard many times, so I basically store the result of the scratchcard in the "scratchcards" list at a certain index. I think my code is quite fast compared to other solutions on reddit.











