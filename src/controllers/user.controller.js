import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from '../utils/ApiError.js'
import {User} from '../models/user.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import {ApiResponse} from '../utils/ApiResponse.js'
import jwt from 'jsonwebtoken' 
import mongoose from "mongoose";

const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        // console.log(user);
        
        const accessToken= await user.generateAccessToken()
        const refreshToken= await user.generateRefreshToken()
        
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave:false})
        console.log(user.refreshToken);
        
        return{accessToken,refreshToken}

    } catch (error) {
        throw new ApiError(500,"something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler(async (req,res)=>{
    //get user details from frontend
    // validation - not empty
    // check if user already exists : username,email
    // check for images , check for avatar
    //upload them to cloudinary ,avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    //return res

    // getting user details from postman
    // console.log("req.body",req.body);
    
    const {fullname,email,username,password} = req.body
    // console.log("email",email);
    
    // validating 
    if (
        [fullname,email,username,password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400,"All fields are required")
    }

    // checking whether user already exist
    const existedUser = await User.findOne({
        $or :[{ username},{email}]
    })

    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }
    // console.log("req.files this is due to multer ehicch is middleware that we added",req.files);
    
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath=req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length >0 )
    {
        coverImageLocalPath = req.files.coverImage[0].path
    }
    
    if (!avatarLocalPath) {
        throw new ApiError(400,"Avatar file is required")
    }

    const  avatar=await uploadOnCloudinary(avatarLocalPath)
    // console.log("avatar details sent by cloudinary, after we uploaded the picture there",avatar);
    
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    // console.log(coverImage);
    
    
    if (!avatar) {
        throw new ApiError(400,"Avatar file is required")
    }

    const user = await User.create({
        fullname,
        avatar:avatar.url,
        coverImage:coverImage?.url || " ",
        email,
        password,
        username:username.toLowerCase()
    })
    // console.log(user);
    

    const createdUser =await User.findById(user._id).select(
        "-password -refreshToken"
    )
    console.log(createdUser);
    

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering")
    }
    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered Succesfully")
    )
})

const loginUser = asyncHandler(async (req,res)=>{
      // req body => data
      // username or email
      //find the user
      //password check
      //access and refresh token
      //send cookie

      const {email,username,password} = req.body

      if (!username && !email) {
        throw new ApiError(400,"username or email is required")
      }

      const user = await User.findOne({
        $or:[{username},{email}]
      })

      if (!user) {
        throw new ApiError(404,"User does not exist")
      }

      const isPasswordValid= await user.isPasswordCorrect(password)

      if (!isPasswordValid) {
        throw new ApiError(401,"Invalid user credentials")
      }
      
      const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)
      const loggesdInUser=await User.findById(user._id).select("-password -refreshToken")

      const options ={
        httpOnly:true,
        secure:true
      }

      return res
      .status(200)
      .cookie("accessToken",accessToken,options)
      .cookie("refreshToken",refreshToken,options)
      .json(
        new ApiResponse(200,
            {
               user:loggesdInUser,accessToken,refreshToken
            },
            "User logged in Successfully"
        )
    )
})
 
const logoutUser = asyncHandler(async(req,res)=>{
    console.log("finding the error at the first line of logout usr function");
    
     await User.findByIdAndUpdate(req.user._id,
        {
          $set:{
            refreshToken:undefined
          }  
        },
        {
            new:true
        }
     )
     const options={
        httpOnly:true,
        secure:true
     }
     
     return res
     .status(200)
     .clearCookie("accessToken",options)
     .clearCookie("refreshToken",options)
     .json(new ApiResponse(200,{},"user logged out"))
})

const refreshAccessToken = asyncHandler(async(req,res)=>{
         const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

         if (!incomingRefreshToken) {
            throw new ApiError(401,"unauthorized request")
         }

         try {
            const decodedToken=jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
   
            const user = await User.findById(decodedToken?._id)
   
            if (!user) {
               throw new ApiError(401," Invalid refresh token")
            }
   
            if (incomingRefreshToken !== user?.refreshToken) {
               throw new ApiError(401," refresh token is expired or used")
            }
            
            const options ={
               httpOnly:true,
               secure:true
            }
            const {accessToken,newRefreshToken}=await generateAccessAndRefreshTokens(user._id)
   
            return res
            .status(200)
            .cookie("accessToken",accessToken,options)
            .cookie("refreshToken",newRefreshToken,options)
            .json(
               new ApiResponse(
                   200,
                   {accessToken,refreshToken:newRefreshToken},
                   "Access token refreshed"
               )
            )
         } catch (error) {
            throw new ApiError(401,error?.message || "Invalid refresh token")
         }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken
}