package common
var PopDataExample = []string{

	`
		{
			"id": "uuid-4561",
			"city": "New York",
			"lng": -74.2,
			"lat": 40.6,
			"user": {"name":  "201", "id":"user-001"},
			"bandwidth": 100,
			"bandwidthInUse": 30,
			"interceptStop": 102,
			"TotalPolicies": 400,
			"links": ["uuid-4562", "uuid-4563", "uuid-4565", "uuid-4567", "uuid-4568","uuid-4569"],
			"status":"Online"
		}
	`,
	`
		{
			"id": "uuid-4562",
			"city": "Atlanta",
			"lng": -84.5,
			"lat": 33.7,
			"user": {"name":  "97", "id":"user-002"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 209,
			"TotalPolicies": 500,
			"links": ["uuid-4563", "uuid-4566"],
			"status":"Online"
		}
	`,
	`
		{
			"id": "uuid-4563",
			"city": "San Francisco",
			"lng": -122.25,
			"lat": 37.46,
			"user": {"name":  "97", "id":"user-001"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 332,
			"TotalPolicies": 500,
			"links": ["uuid-4564", "uuid-4567"],
			"status":"Online"
		}
	`,
	`
		{
			"id": "uuid-4564",
			"city": "New Orleans",
			"lng": -90.0,
			"lat": 30.0,
			"user": {"name":  "97", "id":"user-003"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 457,
			"TotalPolicies": 500,
			"status":"Online"
		}
	`,
	`
		{
			"id": "uuid-4565",
			"city": "Dubai",
			"lng": 55.3,
			"lat": 25.3,
			"links": ["uuid-4568"],
			"user": {"name":  "97", "id":"user-001"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 546,
			"TotalPolicies": 500,
			"status":"Online"
		}
	`,
	`
		{
			"id": "uuid-4566",
			"city": "Las Vegas",
			"lng": -115.3,
			"lat": 36.1,
			"user": {"name":  "97", "id":"user-001"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 667,
			"TotalPolicies": 500,
			"status":"Error"
		}
	`,
	`
		{
			"id": "uuid-4567",
			"city": "Los Angeles",
			"lng": -118.6,
			"lat": 34.0,
			"user": {"name":  "97", "id":"user-001"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 701,
			"TotalPolicies": 500,
			"status":"Warning"
		}
	`,
	`
		{
			"id": "uuid-4568",
			"city": "London",
			"lng": -0.12,
			"lat": 51.5,
			"user": {"name":  "97", "id":"user-001"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 701,
			"TotalPolicies": 500,
			"status":"Offline"
		}
	`,
	`
		{
			"id": "uuid-4570",
			"city": "Shanghai",
			"lng": 121.2,
			"lat": 31.2,
			"user": {"name":  "97", "id":"user-001"},
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 701,
			"TotalPolicies": 500,
			"status":"Warning",
			"links": ["uuid-4567"]
		}
	`}