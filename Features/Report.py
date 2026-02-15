
print("you can report usefull information through CommUnity")



user_reports = input("Write your report below:   \n")

#print(user_reports)

with open("report.txt","a") as file:
	file.write(user_reports + "\n")

print("your report has been submitted thanks for you contribution")