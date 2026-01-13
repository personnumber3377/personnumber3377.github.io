
# Day 1

Ok, so I think this is actually quite easy. Just sort both of the lists of ints and then go through them one by one.

## The solution

Maybe something like this?????

{% raw %}
```




def solve(lines: list[str]) -> int: # Solve function.
	nums1 = []
	nums2 = []
	for string in lines:
		num1, num2 = string.split("   ")
		nums1.append(int(num1))
		nums2.append(int(num2))

	nums1.sort()
	nums2.sort()

	diffs = [abs(x[0] - x[1]) for x in zip(nums1,nums2)]
	return sum(diffs)

if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()

	res = solve(lines)

	print("Result: "+str(res))


	exit(0)

```
{% endraw %}

That seems to work!

# Part 2

Ok, so I suspect that part 2 will be a bit more difficult...

## Bug.

Ok, so I think that this should work here:

{% raw %}
```


PART = 2

def part1(lines: list[str]) -> int: # Solve function.
	nums1 = []
	nums2 = []
	for string in lines:
		num1, num2 = string.split("   ")
		nums1.append(int(num1))
		nums2.append(int(num2))

	nums1.sort()
	nums2.sort()

	diffs = [abs(x[0] - x[1]) for x in zip(nums1,nums2)]
	return sum(diffs)

def count_nums(nums) -> dict: # This generates a dictionary with number as key and how many occurences as value.
	o = {}
	for num in nums:
		if num not in o:
			o[num] = 1
		else:
			o[num] += 1
	return o

def calculate_similarity_score(nums1, nums2) -> int:
	count1, count2 = count_nums(nums1), count_nums(nums2)
	print(count1)
	print(count2)
	return sum([count1[key]*count2[key] if key in count2 else 0 for key in count1.keys()]) # No need to check the other way, because numbers which are only in count2 don't count towards the total anyway.

def part2(lines: list[str]) -> int: # Solve function.
	nums1 = []
	nums2 = []
	for string in lines:
		num1, num2 = string.split("   ")
		nums1.append(int(num1))
		nums2.append(int(num2))

	out = calculate_similarity_score(nums1, nums2)

	return out

if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()
	if PART == 1:
		res = part1(lines)
	elif PART == 2:
		res = part2(lines)
	else:
		print("Invalid part: "+str(PART))
		exit(1)
	print("Result: "+str(res))


	exit(0)


```
{% endraw %}

but it produces 10 for the toy example not 31 which is the expected. Let's add a debug statement showing the multiplication list.

Aaaaaahh. I see.

{% raw %}
```

The first number in the left list is 3. It appears in the right list three times, so the similarity score increases by 3 * 3 = 9.
The second number in the left list is 4. It appears in the right list once, so the similarity score increases by 4 * 1 = 4.
The third number in the left list is 2. It does not appear in the right list, so the similarity score does not increase (2 * 0 = 0).
The fourth number, 1, also does not appear in the right list.
The fifth number, 3, appears in the right list three times; the similarity score increases by 9.
The last number, 3, appears in the right list three times; the similarity score again increases by 9.


```
{% endraw %}


the numbers are counted twice basically.

If the left side has three "3" numbers aka the number "3" occurs three times and in the right side there is one three ("3") number, then the total is increased by `(3*1+3*1+3*1)` because we add the product on each occurence of "3", so therefore I think we can just do this: `count1[key]*count2[key]*key` instead of just `count1[key]*count2[key]` because I had a brain fart and I didn't multiply by the number actually :D .

Now it works!


