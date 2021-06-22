# Based on
# https://www.le arnopencv.com/pytorch-for-beginners-image-classification-using-pre-trained-models/

# Import torch and torchvision modules
import torch
from torchvision import models, transforms
from PIL import Image  # Import Pillow
from typing import Tuple, List


class AlexNetInference:
    def __init__(self) -> None:
        # Load the pre-trained model from a file
        self.alexnet = torch.load("/app/alexnet-pretrained.pt")
        self.transform = transforms.Compose(
            [
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]
                ),
            ]
        )
        with open("/app/imagenet_classes.txt") as f:
            self.classes = [line.strip() for line in f.readlines()]

    def evaluate(self, image_path: str, results_num: int) -> List[Tuple]:
        # Load the test image.
        image = Image.open(image_path)

        image_t = self.transform(image)
        batch_t = torch.unsqueeze(image_t, 0)
        self.alexnet.eval()
        out = self.alexnet(batch_t)

        _, indices = torch.sort(out, descending=True)
        percentage = torch.nn.functional.softmax(out, dim=1)[0] * 100

        return [
            (self.classes[idx], percentage[idx].item()) for idx in indices[0][:results_num]
        ]

    def evaluate_formatted(self, image_path, results_num=5) -> str:
        results = self.evaluate(image_path, results_num)
        output = "\n".join(["\t" + str(r) for r in results])
        return f"Return top {results_num} inference results:\n" + output
