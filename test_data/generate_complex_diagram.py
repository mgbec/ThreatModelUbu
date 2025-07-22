#!/usr/bin/env python3
"""
Generate a more complex architectural diagram with various component types.
"""

import cv2
import numpy as np

# Create a blank white image
width, height = 1200, 900
image = np.ones((height, width, 3), dtype=np.uint8) * 255

# Draw components with clearer shapes and labels

# 1. Database (circle)
cv2.circle(image, (200, 200), 60, (0, 0, 0), 2)
cv2.putText(image, "Database", (160, 200), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 2. API Gateway (wide rectangle)
cv2.rectangle(image, (400, 150), (650, 220), (0, 0, 0), 2)
cv2.putText(image, "API Gateway", (450, 195), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 3. Lambda Function (square)
cv2.rectangle(image, (450, 300), (550, 400), (0, 0, 0), 2)
cv2.putText(image, "Lambda", (470, 350), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 4. S3 Bucket (rounded rectangle - approximated with a rectangle)
cv2.rectangle(image, (700, 150), (850, 250), (0, 0, 0), 2)
cv2.putText(image, "S3 Bucket", (730, 200), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 5. Server (tall rectangle)
cv2.rectangle(image, (150, 400), (220, 600), (0, 0, 0), 2)
cv2.putText(image, "Server", (160, 500), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 6. Network component (hexagon)
pts = np.array([[700, 400], [775, 370], [850, 400], [850, 470], [775, 500], [700, 470]], np.int32)
pts = pts.reshape((-1, 1, 2))
cv2.polylines(image, [pts], True, (0, 0, 0), 2)
cv2.putText(image, "Network", (740, 435), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 7. User (circle with stick figure)
cv2.circle(image, (900, 500), 40, (0, 0, 0), 2)
# Draw stick figure inside
cv2.line(image, (900, 480), (900, 520), (0, 0, 0), 2)  # body
cv2.line(image, (900, 490), (880, 510), (0, 0, 0), 2)  # left arm
cv2.line(image, (900, 490), (920, 510), (0, 0, 0), 2)  # right arm
cv2.line(image, (900, 520), (880, 540), (0, 0, 0), 2)  # left leg
cv2.line(image, (900, 520), (920, 540), (0, 0, 0), 2)  # right leg
cv2.circle(image, (900, 465), 15, (0, 0, 0), 2)  # head
cv2.putText(image, "User", (880, 560), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# 8. Load Balancer (trapezoid)
pts = np.array([[300, 650], [400, 600], [500, 600], [600, 650]], np.int32)
pts = pts.reshape((-1, 1, 2))
cv2.polylines(image, [pts], True, (0, 0, 0), 2)
cv2.putText(image, "Load Balancer", (400, 635), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

# Draw connections with thicker lines and labels

# 1. Database to API Gateway
cv2.line(image, (260, 200), (400, 185), (0, 0, 0), 2)
cv2.putText(image, "Query", (320, 175), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 2. API Gateway to Lambda
cv2.line(image, (525, 220), (500, 300), (0, 0, 0), 2)
cv2.putText(image, "Invoke", (535, 260), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 3. Lambda to S3
cv2.line(image, (550, 350), (700, 200), (0, 0, 0), 2)
cv2.putText(image, "Store", (600, 250), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 4. Server to Database
cv2.line(image, (185, 400), (185, 260), (0, 0, 0), 2)
cv2.putText(image, "Manage", (150, 330), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 5. Lambda to Network
cv2.line(image, (550, 350), (700, 435), (0, 0, 0), 2)
cv2.putText(image, "Connect", (600, 400), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 6. Network to User
cv2.line(image, (850, 435), (900, 500), (0, 0, 0), 2)
cv2.putText(image, "Access", (860, 470), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 7. User to Load Balancer
cv2.line(image, (900, 540), (600, 625), (0, 0, 0), 2)
cv2.putText(image, "Request", (750, 590), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# 8. Load Balancer to API Gateway
cv2.line(image, (450, 600), (525, 220), (0, 0, 0), 2)
cv2.putText(image, "Route", (475, 400), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)

# Save the image
cv2.imwrite("enhanced/complex_diagram.png", image)
print("Complex test diagram generated: enhanced/complex_diagram.png")
