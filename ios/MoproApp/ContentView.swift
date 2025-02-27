//
//  ContentView.swift
//  MoproApp
//
import SwiftUI
import moproFFI

func serializeOutputs(_ stringArray: [String]) -> [UInt8] {
    var bytesArray: [UInt8] = []
    let length = stringArray.count
    var littleEndianLength = length.littleEndian
    let targetLength = 32
    withUnsafeBytes(of: &littleEndianLength) {
        bytesArray.append(contentsOf: $0)
    }
    for value in stringArray {
        // TODO: should handle 254-bit input
        var littleEndian = Int32(value)!.littleEndian
        var byteLength = 0
        withUnsafeBytes(of: &littleEndian) {
            bytesArray.append(contentsOf: $0)
            byteLength = byteLength + $0.count
        }
        if byteLength < targetLength {
            let paddingCount = targetLength - byteLength
            let paddingArray = [UInt8](repeating: 0, count: paddingCount)
            bytesArray.append(contentsOf: paddingArray)
        }
    }
    return bytesArray
}


struct ContentView: View {
    @State private var textViewText = ""
    @State private var isCircomProveButtonEnabled = true
    @State private var isCircomVerifyButtonEnabled = false
    @State private var generatedCircomProof: String?
    @State private var circomPublicInputs: String?
    private let zkeyPath = Bundle.main.path(forResource: "sha256", ofType: "zkey")!
   private let vkeyPath = Bundle.main.path(forResource: "verification_key", ofType: "json")!
    
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Button("Prove Circom", action: runCircomProveAction).disabled(!isCircomProveButtonEnabled).accessibilityIdentifier("proveCircom")
            Button("Verify Circom", action: runCircomVerifyAction).disabled(!isCircomVerifyButtonEnabled).accessibilityIdentifier("verifyCircom")

            ScrollView {
                Text(textViewText)
                    .padding()
                    .accessibilityIdentifier("proof_log")
            }
            .frame(height: 200)
        }
        .padding()
    }
}

extension ContentView {
    func runCircomProveAction() {
        textViewText += "Generating Circom proof... "
        do {
            // Prepare inputs
//            var inputs = [String: [String]]()
//            let a = 3
//            let b = 5
//            let c = a*b
//            inputs["a"] = [String(a)]
//            inputs["b"] = [String(b)]
    
            //if let jsonData = try? JSONEncoder().encode(inputs),
              // let jsonInputs = String(data: jsonData, encoding: .utf8) {
            let jsonInputs = #"""
{"in":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","0","0","0","0","0","0","1","0","0","0","0","0","0","0","1","1","0","0","0","0","0","1","0","0","0","0","0","0","0","1","0","1","0","0","0","0","0","1","1","0","0","0","0","0","0","1","1","1","0","0","0","0","1","0","0","0","0","0","0","0","1","0","0","1","0","0","0","0","1","0","1","0","0","0","0","0","1","0","1","1","0","0","0","0","1","1","0","0","0","0","0","0","1","1","0","1","0","0","0","0","1","1","1","0","0","0","0","0","1","1","1","1","0","0","0","1","0","0","0","0","0","0","0","1","0","0","0","1","0","0","0","1","0","0","1","0","0","0","0","1","0","0","1","1","0","0","0","1","0","1","0","0","0","0","0","1","0","1","0","1","0","0","0","1","0","1","1","0","0","0","0","1","0","1","1","1","0","0","0","1","1","0","0","0","0","0","0","1","1","0","0","1","0","0","0","1","1","0","1","0","0","0","0","1","1","0","1","1","0","0","0","1","1","1","0","0","0","0","0","1","1","1","0","1","0","0","0","1","1","1","1","0","0","0","0","1","1","1","1","1","0","0","1","0","0","0","0","0","0","0","1","0","0","0","0","1","0","0","1","0","0","0","1","0","0","0","1","0","0","0","1","1","0","0","1","0","0","1","0","0","0","0","1","0","0","1","0","1","0","0","1","0","0","1","1","0","0","0","1","0","0","1","1","1","0","0","1","0","1","0","0","0","0","0","1","0","1","0","0","1","0","0","1","0","1","0","1","0","0","0","1","0","1","0","1","1","0","0","1","0","1","1","0","0","0","0","1","0","1","1","0","1","0","0","1","0","1","1","1","0","0","0","1","0","1","1","1","1","0","0","1","1","0","0","0","0","0","0","1","1","0","0","0","1","0","0","1","1","0","0","1","0","0","0","1","1","0","0","1","1","0","0","1","1","0","1","0","0","0","0","1","1","0","1","0","1","0","0","1","1","0","1","1","0","0","0","1","1","0","1","1","1","0","0","1","1","1","0","0","0","0","0","1","1","1","0","0","1","0","0","1","1","1","0","1","0","0","0","1","1","1","0","1","1","0","0","1","1","1","1","0","0","0","0","1","1","1","1","0","1","0","0","1","1","1","1","1","0","0","0","1","1","1","1","1","1","0","1","0","0","0","0","0","0","0","1","0","0","0","0","0","1","0","1","0","0","0","0","1","0","0","1","0","0","0","0","1","1","0","1","0","0","0","1","0","0","0","1","0","0","0","1","0","1","0","1","0","0","0","1","1","0","0","1","0","0","0","1","1","1","0","1","0","0","1","0","0","0","0","1","0","0","1","0","0","1","0","1","0","0","1","0","1","0","0","1","0","0","1","0","1","1","0","1","0","0","1","1","0","0","0","1","0","0","1","1","0","1","0","1","0","0","1","1","1","0","0","1","0","0","1","1","1","1","0","1","0","1","0","0","0","0","0","1","0","1","0","0","0","1","0","1","0","1","0","0","1","0","0","1","0","1","0","0","1","1","0","1","0","1","0","1","0","0","0","1","0","1","0","1","0","1","0","1","0","1","0","1","1","0","0","1","0","1","0","1","1","1","0","1","0","1","1","0","0","0","0","1","0","1","1","0","0","1","0","1","0","1","1","0","1","0","0","1","0","1","1","0","1","1","0","1","0","1","1","1","0","0","0","1","0","1","1","1","0","1","0","1","0","1","1","1","1","0","0","1","0","1","1","1","1","1","0","1","1","0","0","0","0","0","0","1","1","0","0","0","0","1","0","1","1","0","0","0","1","0","0","1","1","0","0","0","1","1","0","1","1","0","0","1","0","0","0","1","1","0","0","1","0","1","0","1","1","0","0","1","1","0","0","1","1","0","0","1","1","1","0","1","1","0","1","0","0","0","0","1","1","0","1","0","0","1","0","1","1","0","1","0","1","0","0","1","1","0","1","0","1","1","0","1","1","0","1","1","0","0","0","1","1","0","1","1","0","1","0","1","1","0","1","1","1","0","0","1","1","0","1","1","1","1","0","1","1","1","0","0","0","0","0","1","1","1","0","0","0","1","0","1","1","1","0","0","1","0","0","1","1","1","0","0","1","1","0","1","1","1","0","1","0","0","0","1","1","1","0","1","0","1","0","1","1","1","0","1","1","0","0","1","1","1","0","1","1","1","0","1","1","1","1","0","0","0","0","1","1","1","1","0","0","1","0","1","1","1","1","0","1","0","0","1","1","1","1","0","1","1","0","1","1","1","1","1","0","0","0","1","1","1","1","1","0","1","0","1","1","1","1","1","1","0","0","0","0","0","0","0","0","0"]}
"""#

            // Expected outputs
                //let outputs: [String] = [String(c), String(a)]
                //let expectedOutput: [UInt8] = serializeOutputs(outputs)
                
                let start = CFAbsoluteTimeGetCurrent()
                
                // Generate Proof
                let generateProofResult = try generateCircomProof(zkeyPath: zkeyPath, inputsJson: jsonInputs)
                assert(!generateProofResult.proof.isEmpty, "Proof should not be empty")
//                assert(Data(expectedOutput) == generateProofResult.inputs, "Circuit outputs mismatch the expected outputs")
                
                let end = CFAbsoluteTimeGetCurrent()
                let timeTaken = end - start
                
                // Store the generated proof and public inputs for later verification
                generatedCircomProof = generateProofResult.proof
                circomPublicInputs = generateProofResult.inputs
                
                textViewText += "\(String(format: "%.3f", timeTaken))s 1️⃣\n"
                textViewText += "Proof: \(String(describing: generatedCircomProof))\n"
                textViewText += "Inputs: \(String(describing: circomPublicInputs))\n"
                
                isCircomVerifyButtonEnabled = true
            //}
            
            
        } catch {
            textViewText += "\nProof generation failed: \(error.localizedDescription)\n"
        }
    }
    
    func runCircomVerifyAction() {
        guard let proof = generatedCircomProof,
              let inputs = circomPublicInputs else {
            textViewText += "Proof has not been generated yet.\n"
            return
        }
        
        textViewText += "Verifying Circom proof... "
        do {
            let start = CFAbsoluteTimeGetCurrent()
            let vkey = try String(contentsOfFile: vkeyPath, encoding: .utf8)
            let isValid = try verifyCircomProof(
                vkey: vkey,
                proof: proof,
                publicInput: inputs
            )
            let end = CFAbsoluteTimeGetCurrent()
            let timeTaken = end - start
            
            if isValid {
                textViewText += "\(String(format: "%.3f", timeTaken))s 2️⃣\n"
            } else {
                textViewText += "\nProof verification failed.\n"
            }
            isCircomVerifyButtonEnabled = false
        } catch let error as MoproError {
            print("\nMoproError: \(error)")
        } catch {
            print("\nUnexpected error: \(error)")
        }
    }
}

