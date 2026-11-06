# Analysis Queries Used

## 1. Confirmed Indexed Data
```source="tutorialdata.zip:*"
```

## 2. Search for Fails
```fail*
```

## 3. Search data for 404s
```status=404
```

## 4. Aggregate response codes
```source="tutorialdata.zip:*/access.log" | stats count by status
```

## 5. Identify top 10 IPs
```source="tutorialdata.zip:*/access.log" | stats count by clientip | sort -count | head 10
```

## 6. Find failed SSH login attempts
```source="tutorialdata.zip:*/secure.log" "Failed password"
```

## 7. Pipe top 10 IPs with failed SSH login attempts
```source="tutorialdata.zip:*/secure.log" "Failed password" | stats count by src_ip
```
-----
# Dashboard Queries

## 1. Panel for failed logins
```source="tutorialdata.zip:*/secure.log" "Failed password" | stats count AS "Failed Logins"
```
## 2. Displays requests per IP
```source="tutorialdata.zip:*/access.log" | stats count by clientip | sort -count | head 10
```
## 3. HTTP error codes
```source="tutorialdata.zip:*/access.log" status>=400 | stats count by status
```