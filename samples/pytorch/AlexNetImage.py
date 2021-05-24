# Based on
# https://www.learnopencv.com/pytorch-for-beginners-image-classification-using-pre-trained-models/

# Import torch and torchvision modules
import torch
from torchvision import models

# Load the pre-trained model from a file
alexnet = torch.load("/app/alexnet-pretrained.pt")

from torchvision import transforms
transform = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
    transforms.Normalize(
    mean=[0.485, 0.456, 0.406],
    std=[0.229, 0.224, 0.225]
)])

# Import Pillow
from PIL import Image
# Load the test image.
img = Image.open("/app/dog.jpg")

img_t = transform(img)
batch_t = torch.unsqueeze(img_t, 0)
alexnet.eval()
out = alexnet(batch_t)

with open('/app/imagenet_classes.txt') as f:
    classes = [line.strip() for line in f.readlines()]

_, indices = torch.sort(out, descending=True)
percentage = torch.nn.functional.softmax(out, dim=1)[0] * 100

# Show the top 5 predictions.
print([(classes[idx], percentage[idx].item()) for idx in indices[0][:5]])