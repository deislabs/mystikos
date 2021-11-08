# Based on
# https://www.learnopencv.com/pytorch-for-beginners-image-classification-using-pre-trained-models/

# Import torch and torchvision modules
import torch
from torchvision import models, transforms
from PIL import Image  # Import Pillow
import onnxruntime
from typing import Tuple, List


class AlexNetInference:
    def __init__(self) -> None:
        # Load the pre-trained model from a file
        self.alexnet_onnx = onnxruntime.InferenceSession("/app/alexnet-pretrained.onnx")
        self.alexnet_pt = torch.load("/app/alexnet-pretrained.pt")
        
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

    def evaluate(self, image_path: str, results_num: int, is_onnx: bool) -> List[Tuple]:
        # Load the test image.
        image = Image.open(image_path)

        image_t = self.transform(image)
        batch_t = torch.unsqueeze(image_t, 0)

        if is_onnx:
            # ONNX Runtime
            ort_inputs = {self.alexnet_onnx.get_inputs()[0].name: batch_t.cpu().numpy().astype('float32')}
            ort_outs = self.alexnet_onnx.run(None, ort_inputs)
            out = torch.from_numpy(ort_outs[0])
        else:
            # PyTorch
            self.alexnet_pt.eval()
            out = self.alexnet_pt(batch_t)

        _, indices = torch.sort(out, descending=True)
        percentage = torch.nn.functional.softmax(out, dim=1)[0] * 100

        return [
            (self.classes[idx], percentage[idx].item()) for idx in indices[0][:results_num]
        ]

    def evaluate_formatted(self, image_path, results_num=5) -> str:
        results_pt = self.evaluate(image_path, results_num, False)
        output_pt = "\n".join(["\t" + str(r) for r in results_pt])
        results_onnx = self.evaluate(image_path, results_num, True)
        output_onnx = "\n".join(["\t" + str(r) for r in results_onnx])
        return f"ONNX Runtime top {results_num} inference results:\n" + output_onnx +\
            f"\nPyTorch top {results_num} inference results:\n" + output_pt
